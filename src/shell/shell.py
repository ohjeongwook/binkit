import os
import sys

import pprint
import json

import cmd

try:
    import idaapi
    idadir = idaapi.get_user_idadir()
except:
    idadir = os.path.join(os.environ['USERPROFILE'], r'AppData\Roaming\Hex-Rays\IDA Pro')
plugins_folder = os.path.join(idadir, "plugins")

binkit_paths = [os.path.join(plugins_folder, "binkit")]

for binkit_path in binkit_paths:
    print("Adding path: %s" % binkit_path)
    sys.path.insert(0, binkit_path)

import client
import pybinkit
from matches import *

class BinKitShell(cmd.Cmd):
    intro = 'Welcome to the binkit shell.\n - Type help or ? to list commands.\n'
    prompt = '(binkit) '

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.binaries = []
        self.profiles = client.Profiles()

    def do_s(self, arg):
        'List current IDA sessions'
        self.do_sessions(arg)

    def do_sessions(self, arg):
        'List current IDA sessions'
        self.profile_list = self.profiles.list()
        index = 0
        
        for profile in self.profile_list:
            print('# Index: %d' % index)
            for k,v in profile.items():
                print('    %s: %s' % (k, str(v)))
            index += 1

    def do_export(self, arg):
        'Export IDA analysis data to a database'
        args = arg.split()
        
        index = 0
        filename = ''
        if len(args) > 0:
            index = int(args[0])
            if len(args) > 1:
                filename = args[1]            

        if index >= len(self.profile_list):
            print("Index is bigger than %d" % len(self.profile_list))
        else:
            print(self.profile_list[index])
            if not filename:
                filename = '%s.db' % self.profile_list[index]['md5']

        filename = os.path.abspath(filename)
        connection = client.IDASessions.connect(self.profile_list[index]['md5'])
        connection.root.export(filename)
        
    def do_load(self, arg):
        for filename in arg.split():
            binary = pybinkit.Binary()
            binary.open(filename)
            self.binaries.append(binary)
            
    def do_list(self, arg):
        for binary in self.binaries:
            print(binary.get_md5())

    def do_diff(self, arg):
        if len(self.binaries) < 2:
            return

        if arg == '':
            diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
            self.basic_block_matches = diff_algorithms.do_instruction_hash_match()
            #for match in self.basic_block_matches:
            #    pprint.pprint('%.8x - %.8x (%d)' % (match.source, match.target, match.match_rate))

            self.function_matches = pybinkit.FunctionMatches(self.binaries[0], self.binaries[1])
            self.function_matches.add_matches(self.basic_block_matches)

        elif arg == 'ins':
            self.function_matches.do_instruction_hash_match()

        elif arg == 'cf':
            self.function_matches.do_control_flow_match()

        self.print_function_matches()

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

    def do_save(self, arg):
        function_match_storage = FunctionMatchStorageLoader.load(self.function_matches, binaries = self.binaries)
        function_match_storage.sort()
        function_match_storage.save(arg)

    def do_show(self, arg):
        if arg:
            filename = os.path.abspath(arg)
        else:
            filename = os.path.abspath('temp.json')

        if not os.path.isfile(filename):
            self.do_save(filename)

        profile_list = self.profiles.list()
        for index in range(0, len(profile_list), 1):
            try:
                connection = client.IDASessions.connect(profile_list[index]['md5'])
            except:
                traceback.print_exc()
                continue
            connection.root.show_diff(filename)

    def do_quit(self, arg):
        'Quit shell.'
        return True

    def do_q(self, arg):
        'Quit shell.'
        return True

    def close(self):
        pass

def parse(arg):
    return tuple(map(int, arg.split()))

if __name__ == '__main__':
    BinKitShell().cmdloop()
