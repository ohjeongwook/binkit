import os
import sys
import traceback

try:
    import idaapi
    idadir = idaapi.get_user_idadir()
except:
    idadir = os.path.join(os.environ['USERPROFILE'], r'AppData\Roaming\Hex-Rays\IDA Pro')
plugins_folder = os.path.join(idadir, "plugins")
binkit_paths = [os.path.join(plugins_folder, "binkit")]

for binkit_path in binkit_paths:
    print("Adding path: %s" % binkit_path)
    sys.path.append(binkit_path)

import pybinkit
import client
from function_match import *

matchTypeMap = {
    "CALL":  0,
    "CREF_FROM":  1,
    "CREF_TO":  2,
    "DREF_FROM":  3,
    "DREF_TO":  4,
    "CALLED":  5
}

class BinaryMatcher:
    def __init__(self, log_setting_filename = ''):
        self.function_matches = None
        self.binaries = []        
        self.profiles = client.Profiles()
        pybinkit.load_log_settings(log_setting_filename)

    def get_binaries(self):
        return self.binaries

    def get_profiles(self):
        self.profile_list = self.profiles.list()
        return self.profile_list

    def export(self, filename, index = 0):
        if index >= len(self.profile_list):
            print("Index is bigger than %d" % len(self.profile_list))
        else:
            print(self.profile_list[index])
            if not filename:
                filename = '%s.db' % self.profile_list[index]['md5']

        filename = os.path.abspath(filename)
        connection = client.IDASessions.connect(self.profile_list[index]['md5'])
        connection.root.export(filename)

    def load(self, filename):
        print('load: %s' % filename)
        self.binaries.append(pybinkit.Binary(filename))

    def diff(self, algorithm = 'init', match_type = 'CREF_FROM', iteration = 1):
        print('diff algorithm: %s' % algorithm)
        total_match_count = 0
        if len(self.binaries) < 2:
            return total_match_count

        match_type = matchTypeMap.get(match_type.upper(), 1)
        if self.function_matches == None or algorithm == 'init':
            diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
            self.basic_block_matches = diff_algorithms.do_instruction_hash_match()
            total_match_count += len(self.basic_block_matches)
            self.function_matches = pybinkit.FunctionMatching(self.binaries[0], self.binaries[1])
            self.function_matches.add_matches(self.basic_block_matches)

        i = 0
        while i < iteration:
            current_match_count = 0
            if algorithm == ('inshash', 'hash'):
                print('* do_instruction_hash_match:')
                current_match_count = self.function_matches.do_instruction_hash_match()
            elif algorithm in ('cf', 'controlflow'):
                print('* do_control_flow_match:')
                current_match_count = self.function_matches.do_control_flow_match(0, match_type)
            print('  current_match_count: %d' % current_match_count)
            total_match_count += current_match_count            
            if current_match_count == 0:
                break
            i += 1

        print('  total_match_count: %d' % total_match_count)
        return total_match_count

    def print_function_matches(self):
        function_match_tool = FunctionMatchTool(self.function_matches, binaries = self.binaries)
        print(function_match_tool.get_stats())
        """
        for function_match in util.get_function_match_list():
            print('* %.8x - %.8x' % (function_match['source'], function_match['target']))
            if 'matches' in function_match:
                for match in function_match['matches']:
                    print('    -%.8x - %.8x (%d)' % (match['source'], match['target'], match['match_rate']))
        """

    def save(self, filename):
        if not self.function_matches:
            return
        function_match_tool = FunctionMatchTool(self.function_matches, binaries = self.binaries)
        function_match_storage = function_match_tool.get_function_match_file()
        print("Saving diff snapshot to " + filename)
        function_match_storage.save(filename)

    def show_on_ida(self, filename):
        profile_list = self.profiles.list()
        for index in range(0, len(profile_list), 1):
            try:
                connection = client.IDASessions.connect(profile_list[index]['md5'])
            except:
                traceback.print_exc()
                continue

            if not connection or not connection.root:
                continue

            connection.root.show_diff(filename)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='BinKit BinaryMatcher')
    parser.add_argument('-c', '--command', metavar='command', type=str, default = '', help='File script command')
    parser.add_argument('-o', '--output_filename', metavar='output_filename', type=str, default = 'diff.yml', help='Output filename')
    parser.add_argument('filenames', metavar='filenames', nargs='+', type=str, help='IDAPython script filename')
    args = parser.parse_args()

    binary_matcher = BinaryMatcher()
    for filename in args.filenames:
        binary_matcher.load(filename)

    match_count = binary_matcher.diff(algorithm = 'init')
    while match_count > 0:
        match_count = binary_matcher.diff(algorithm = 'hash')
        binary_matcher.print_function_matches()

        for matchType in matchTypeMap:
            match_count += binary_matcher.diff(algorithm = 'controlflow', match_type = matchType, iteration = 100)
        binary_matcher.print_function_matches()
    binary_matcher.save(args.output_filename)
