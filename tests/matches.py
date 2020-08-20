import os
import sys
import json
import pprint
import traceback

import pybinkit

class Util:
    def __init__(self, binaries):
        self.debug_level = 0
        self.binaries = binaries

    def get_basic_blocks_set(self, binary, address):
        basic_blocks = {}
        function = binary.get_function(address)

        if not function:
            return

        for basic_block_address in function.get_basic_blocks():
            basic_blocks[basic_block_address] = 1
        return basic_blocks

    def get_function_unidentified_blocks(self, function_match, source_function_address = 0, level = 0):
        prefix = '\t' * level
        (src_binary, target_binary) = self.binaries
        if source_function_address !=0 and source_function_address != function_match.source:
            return {}

        unidentified_blocks = {}
        src_basic_blocks = self.get_basic_blocks_set(src_binary, function_match.source)
        target_basic_blocks = self.get_basic_blocks_set(target_binary, function_match.target)
        
        for match in function_match.match_data_list:
            if match.source in src_basic_blocks:
                del src_basic_blocks[match.source]

            if match.target in target_basic_blocks:
                del target_basic_blocks[match.target]

        if len(src_basic_blocks) > 0 or len(target_basic_blocks) > 0:
            unidentified_blocks = {'sources': [], 'targets': []}
            for source in src_basic_blocks.keys():
                unidentified_blocks['sources'].append({'start': source})
            
            for target in target_basic_blocks.keys():
                unidentified_blocks['targets'].append({'start': target})

            if self.debug_level > 0:
                print(prefix + '%x - %x' % (function_match.source, function_match.target))
                print(prefix + '\t- src:')

                for src_basic_block in src_basic_blocks.keys():
                    print(prefix + '\t%.8x' % src_basic_block)

                print('\t- target:')
                for target_basic_block in target_basic_blocks.keys():
                    print(prefix + '\t%.8x' % target_basic_block)

        return unidentified_blocks

    def get_match_list(self, matches, level = 1):
        prefix = '\t' * level
        match_list = []
        for match in matches:
            if self.debug_level > 0:
                print(prefix + 'Match: %x vs %x - match_rate: %d' % (match.source, match.target, match.match_rate))

            match_list.append({
                'source_parent': match.source_parent,
                'target_parent': match.target_parent,
                'source': match.source,
                'target': match.target,
                'type': match.type,
                'sub_type': match.sub_type,
                'match_rate': match.match_rate
            })

        return match_list

    def print_matches(self, matches, prefix = '', print_disasm = False):
        (src_binary, target_binary) = self.binaries
        src_basic_blocks = src_binary.get_basic_blocks()
        target_basic_blocks = target_binary.get_basic_blocks()

        source_to_target_map = {}
        for match in matches:
            if not match['source'] in source_to_target_map:
                source_to_target_map[match['source']] = []
            source_to_target_map[match['source']].append(match['target'])

            print(prefix + 'Match: %x - %x' % (match['source'], match['target']))
            print(prefix + '    source_parent: %.8x' % match['source_parent'])
            print(prefix + '    target_parent: %.8x' % match['target_parent'])
            print(prefix + '    match_rate: %.8x' % match['match_rate'])

            if print_disasm:
                print(src_basic_blocks.get_disasm_lines(match['source']))
                print('')
                print(target_basic_blocks.get_disasm_lines(match['target']))
                print('')

        for source, targets in source_to_target_map.items():
            print('source: %x targets count: %d' % (source, len(targets)))

    def get_function_match_list(self, function_matches, source_function_address = 0, level = 1):
        prefix = '\t' * level
        function_match_data_list = []
        for function_match in function_matches.get_matches():
            if source_function_address !=0 and source_function_address != function_match.source:
                continue
            
            if self.debug_level > 0:
                print(prefix + 'FunctionMatch: %x vs %x' % (function_match.source, function_match.target))

            function_match_data = {'source': function_match.source, 'target': function_match.target}
            function_match_data['matches'] = self.get_match_list(function_match.match_data_list, level = level + 1)
            unidentified_blocks = self.get_function_unidentified_blocks(function_match, source_function_address)

            if len(unidentified_blocks) > 0:
                function_match_data['unidentified_blocks'] = unidentified_blocks

            function_match_data_list.append(function_match_data)
        return function_match_data_list

    def build_match_map(self, matches):
        matches_map = {}
        for match in matches:
            key = match['source'] << 32 + match['target']
            matches_map[key] = match

        return matches_map

    def build_function_match_map(self, function_matches):
        function_matches_map = {}
        for function_match in function_matches:
            key = function_match['source'] << 32 + function_match['target']
            function_matches_map[key] = function_match

        return function_matches_map

    def compare_matches(self, matches1, matches2, description = ''):
        matches_map1 = self.build_match_map(matches1)
        matches_map2 = self.build_match_map(matches2)

        missing_matches = []
        different_matches = []
        for k, match1 in matches_map1.items():
            if not k in matches_map2:
                missing_matches.append(match1)
                continue

            match2 = matches_map2[k]
            if match1 != match2:
                different_matches.append((match1, match2))

        return (missing_matches, different_matches)

    def compare_function_matches_map(self, function_matches_map1, function_matches_map2, description = ''):
        comparison_result = True
        for k, function_match1 in function_matches_map1.items():
            if not k in function_matches_map2:
                comparison_result = False
                print("* compare_function_matches failed: the source/target match not exists (%s)" % description)
                pprint.pprint(function_match1)
                print('')
                continue

            function_match2 = function_matches_map2[k]
            (missing_matches1, different_matches1) = self.compare_matches(function_match1['matches'], function_match2['matches'], 'orig vs new')
            (missing_matches2, different_matches2) = self.compare_matches(function_match2['matches'], function_match1['matches'], 'new vs orig')

            if len(missing_matches1) > 0 or len(different_matches1) > 0 or len(missing_matches2) > 0 or len(different_matches2) > 0:
                comparison_result = False
                print("* compare_function_matches failed: the source/target match not exists (%s)" % description)

                prefix = ' ' * 4
                indent = 8
                if len(missing_matches1) > 0:
                    print(prefix + '* missing_matches1: %.8x vs %.8x' % (function_match1['source'], function_match1['target']))
                    self.print_matches(missing_matches1, prefix = prefix + (' ' * 4))

                if len(different_matches1) > 0:
                    print(prefix + '* different_matches1: %.8x vs %.8x' % (function_match1['source'], function_match1['target']))
                    print(' ' * indent + pprint.pformat(different_matches1, indent = indent))

                if len(missing_matches2) > 0:
                    print(prefix + '* missing_matches2: %.8x vs %.8x' % (function_match1['source'], function_match1['target']))
                    self.print_matches(missing_matches2, prefix = prefix + (' ' * 4))

                if len(different_matches2) > 0:
                    print(prefix + '* different_matches2: %.8x vs %.8x' % (function_match1['source'], function_match1['target']))
                    print(' ' * indent + pprint.pformat(different_matches2, indent = indent))

        return comparison_result

    def compare_function_matches(self, function_matches1, function_matches2):
        function_matches_map1 = self.build_function_match_map(function_matches1)
        function_matches_map2 = self.build_function_match_map(function_matches2)
        comparison_result1 = self.compare_function_matches_map(function_matches_map1, function_matches_map2, description = 'orig vs new')
        comparison_result2 = self.compare_function_matches_map(function_matches_map2, function_matches_map1, description = 'new vs orig')
        if len(function_matches1) == len(function_matches2) and comparison_result1 and comparison_result2:
            return True

        return False

class FunctionMatchTool:
    def __init__(self, filename = '', function_matches = [], binaries = None):
        self.binaries = binaries
        self.match_results = {'function_matches': function_matches}        
        if filename:
            try:
                with open(filename, 'r') as fd:
                    data = json.load(fd)

                if type(data) is dict and 'function_matches' in data:
                    self.match_results = data
                else:
                    self.match_results['function_matches'] = data
            except:
                traceback.print_exc()

        pprint.pprint(self.match_results)
        self.add_binary_meta_data()
        self.add_basic_block_data()

    def sort_matches(self, matches):
        source_to_match_map = {}
        for match in matches:
            if not match['source'] in source_to_match_map:
                source_to_match_map[match['source']] = []
            source_to_match_map[match['source']].append(match)

        source_list = list(source_to_match_map.keys())
        source_list.sort()

        matches = []
        for source in source_list:
            matches += source_to_match_map[source]
        return matches

    def sort(self):
        source_to_match_map = {}
        for match in self.match_results['function_matches']:
            if 'matches' in match:
                match['matches'] = self.sort_matches(match['matches'])

            if 'source_basic_blocks' in match:
                match['source_basic_blocks'].sort()

            if 'target_basic_blocks' in match:
                match['target_basic_blocks'].sort()

            if not match['source'] in source_to_match_map:
                source_to_match_map[match['source']] = []

            source_to_match_map[match['source']].append(match)

        source_list = list(source_to_match_map.keys())
        source_list.sort()
        self.match_results['function_matches'] = []
        for source in source_list:
            self.match_results['function_matches'] += source_to_match_map[source]

    def add_binary_meta_data(self):
        if not self.binaries:
            return

        self.match_results['binaries'] = {
            'source':
                {
                    'md5': self.binaries[0].get_md5()
                },
            'target':
                {
                    'md5': self.binaries[1].get_md5()
                },
        }

    def add_basic_block_data(self):
        if not self.binaries:
            return

        source_basic_blocks = self.binaries[0].get_basic_blocks()
        target_basic_blocks = self.binaries[1].get_basic_blocks()

        for function_match in self.match_results['function_matches']:
            for basic_block_match in function_match['matches']:
                source_basic_block = source_basic_blocks.get_basic_block(basic_block_match['source'])
                basic_block_match['source_end'] = source_basic_block.end_address
                target_basic_block = target_basic_blocks.get_basic_block(basic_block_match['target'])
                basic_block_match['target_end'] = target_basic_block.end_address

            if 'unidentified_blocks' in function_match:
                for source in function_match['unidentified_blocks']['sources']:
                    source_block = source_basic_blocks.get_basic_block(source['start'])
                    source['end'] = source_block.end_address

                for target in function_match['unidentified_blocks']['targets']:
                    target_block = target_basic_blocks.get_basic_block(target['start'])
                    target['end'] = target_block.end_address

    def write(self, filename):
        with open(filename, 'w') as fd:
            json.dump(self.match_results, fd, indent = 4)

if __name__ == '__main__':
    import os
    import sys
    import glob
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='monitor_memory')    
    parser.add_argument('-c', dest = "command", default = 'sort')
    parser.add_argument('-d', dest = "debug_level", default = 0, type = auto_int)
    parser.add_argument('-a', dest = "address", default = 0x0, type = auto_int)
    parser.add_argument('filenames', metavar='FILENAMES', nargs='+', help = "filenames")
    args = parser.parse_args()

    for filename_pattern in args.filenames:
        for filename in glob.glob(filename_pattern):
            function_match_tool = FunctionMatchTool(filename)
            function_match_tool.sort()
            function_match_tool.write(filename)
