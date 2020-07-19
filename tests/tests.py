import os
import sys
import json
import pprint
import traceback

import unittest
import pybinkit

CALL = 0
CREF_FROM = 1
CREF_TO = 2
DREF_FROM = 3
DREF_TO = 4
CALLED = 5

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

    def get_function_unidentified_blocks(self, function_matches, source_function_address = 0, level = 0):
        prefix = '\t' * level
        unidentified_blocks = []
        (src_binary, target_binary) = self.binaries
        for function_match in function_matches.get_matches():
            if source_function_address !=0 and source_function_address != function_match.source:
                continue

            src_basic_blocks = self.get_basic_blocks_set(src_binary, function_match.source)
            target_basic_blocks = self.get_basic_blocks_set(target_binary, function_match.target)
            
            for match in function_match.match_data_list:
                if match.source in src_basic_blocks:
                    del src_basic_blocks[match.source]

                if match.target in target_basic_blocks:
                    del target_basic_blocks[match.target]

            if len(src_basic_blocks) > 0 or len(target_basic_blocks) > 0:
                unidentified_blocks.append({
                    'source': function_match.source,
                    'target': function_match.target,
                    'source_basic_blocks': list(src_basic_blocks.keys()),
                    'target_basic_blocks': list(target_basic_blocks.keys())
                })
                
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
            function_match_data_list.append(function_match_data)
            #match_data_combinations = diff_algorithms.get_match_data_combinations(function_match.match_data_list)
            #self.print_match_data_combinations(match_data_combinations, '\t')
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

class TestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCase, self).__init__(*args, **kwargs)

        self.debug_level = 0
        self.write_data = True

        self.current_data_directory = 'current'
        self.expected_data_directory = 'expected'

        if self.write_data and not os.path.isdir(self.current_data_directory):
            os.makedirs(self.current_data_directory)
        
        filenames = [r'examples\EPSIMP32-2006.1200.4518.1014\EPSIMP32.db', r'examples\EPSIMP32-2006.1200.6731.5000\EPSIMP32.db']
        self.binaries = []
        for filename in filenames:
            binary = pybinkit.Binary()
            if self.debug_level > 0:
                print('Opening %s...' % filename)
            binary.open(filename)
            self.binaries.append(binary)

        self.util = Util(self.binaries)

    def dump_basic_blocks(self, basic_blocks):
        if self.debug_level > 0:
            print('* dump_basic_blocks:')
        basic_block_data_list = []
        for basic_block_address in basic_blocks.get_addresses():
            basic_block_data = {}
            basic_block_data['address'] = basic_block_address
            symbol = basic_blocks.get_symbol(basic_block_address)
            basic_block_data['symbol'] = symbol
            if self.debug_level > 0:
                if symbol:
                    print('basic_block_address: %.8x: %s' % (basic_block_address, symbol))
                else:
                    print('basic_block_address: %.8x:' % (basic_block_address))

                print('\t'+str(basic_blocks.get_instruction_hash(basic_block_address)))

            basic_block_data['instruction_hash'] = basic_blocks.get_instruction_hash(basic_block_address)

            # CALL, CREF_FROM, CREF_TO, DREF_FROM, DREF_TO, CALLED
            basic_block_data['references'] = []
            for ref_type in range(0, 6, 1):
                for reference in basic_blocks.get_code_references(basic_block_address, ref_type):
                    if self.debug_level > 0:
                        print('\t- [%d] -> %.8x' % (ref_type, reference))
                    basic_block_data['references'].append({'type': ref_type, 'address': reference})

            basic_block_data['parents'] = []
            for parent in basic_blocks.get_parents(basic_block_address):
                if self.debug_level > 0:
                    print('\tparent: %.8x' % (parent))
                basic_block_data['parents'].append(parent)

            basic_block_data_list.append(basic_block_data)

        return basic_block_data_list

    def test_dump_basic_blocks(self):
        basic_block_data_list = []
        for binary in self.binaries:
            basic_blocks = binary.get_basic_blocks()
            basic_block_data_list = self.dump_basic_blocks(basic_blocks)
            basic_block_data_list.append(basic_block_data_list)

        if self.write_data:
            with open(r'current\basic_block_data_list.json', 'w') as fd:
                json.dump(basic_block_data_list, fd, indent = 4)

        with open(r'expected\basic_block_data_list.json', 'r') as fd:
            expected_basic_block_data_list = json.load(fd)

        self.assertEqual(expected_basic_block_data_list, basic_block_data_list)

    def dump_functions(self, binary):
        if self.debug_level > 0:
            print('* dump_functions: ')

        function_data_list = []
        for function in binary.get_functions():
            function_address = function.get_address()
            function_data = {'address': function_address}
            symbol = function.get_symbol()
            function_data['symbol'] = symbol
            function_data['basic_block_addresses'] = []

            if self.debug_level > 0:
                print('%.8x' % function_address)
                print('function_address: %x - %s' % (function_address, symbol))

            for basic_block_address in function.get_basic_blocks():
                if self.debug_level > 0:
                    print('\t%x' % (basic_block_address))

                function_data['basic_block_addresses'].append(basic_block_address)

            function_data['basic_block_addresses'].sort()
            function_data_list.append(function_data)

        return function_data_list

    def test_dump_functions(self):
        function_data_list = []
        for binary in self.binaries:
            function_data_list.append(self.dump_functions(binary))

        if self.write_data:
            with open(r'current\function_data_list.json', 'w') as fd:
                json.dump(function_data_list, fd, indent = 4)

        with open(r'expected\function_data_list.json', 'r') as fd:
            expected_function_data_list = json.load(fd)

            for expected_function_data_list in expected_function_data_list:
                for expected_function_data in expected_function_data_list:
                    expected_function_data['basic_block_addresses'].sort()

        with open(r'expected\function_data_list.json', 'w') as fd:
            json.dump(expected_function_data_list, fd, indent = 4)

        self.assertEqual(expected_function_data_list, function_data_list)

    def test_instruction_hash_match(self):
        if self.debug_level > 0:
            print('* test_instruction_hash_match:')

        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
        matches = diff_algorithms.do_instruction_hash_match()

        match_data_list = []
        for match in matches:
            if self.debug_level > 0:
                print('>> Match: %x vs %x - match_rate: %d' % (match.source, match.target, match.match_rate))
                print('\tPerforming do_control_flow_match:')

            match_data = {'source': match.source, 'target': match.target, 'match_rate': match.match_rate}
            match_data['child_match_list'] = []
            for control_flow_type in (CREF_FROM, ) : #, CALL, DREF_FROM):
                child_matches = diff_algorithms.do_control_flow_match(match.source, match.target, control_flow_type)
                for child_match in child_matches:
                    if self.debug_level > 0:
                        print('\t\t%d: %x - %x vs %x - match_rate: %d' % (control_flow_type, child_match.type, child_match.source, child_match.target, child_match.match_rate))

                    match_data['child_match_list'].append({'control_flow_type': control_flow_type, 'type': child_match.type, 'source': child_match.source, 'target': child_match.target, 'match_rate': child_match.match_rate})

            """
            print('\tPerforming do_control_flow_matches')

            for control_flow_type in (CREF_FROM, ):
                address_pair = pybinkit.AddressPair(match.source, match.target)
                match_data_combinations = diff_algorithms.do_control_flow_matches((address_pair,), control_flow_type)
                print('\tCombinations counts: %d' % (len(match_data_combinations)))
                for match_data_combination in match_data_combinations:
                    print('\t\tMatch Data Combination: count: %d match_rate: %d%%' % (match_data_combination.count(), match_data_combination.get_match_rate()))
                    for i in range(0, match_data_combination.count(), 1):
                        match_data = match_data_combination.get(i)
                        print('\t\t\t%x - %x : %d%%' % (match_data.source, match_data.target, match_data.match_rate))
            """

            match_data_list.append(match_data)

        if self.write_data:
            with open(r'current\match_data_list.json', 'w') as fd:
                json.dump(match_data_list, fd, indent = 4)

        with open(r'expected\match_data_list.json', 'r') as fd:
            expected_match_data_list = json.load(fd)

        self.assertEqual(expected_match_data_list, match_data_list)

    def do_instruction_hash_match_in_functions(self, src_function_address, target_function_address):
        if self.debug_level > 0:
            print('* do_instruction_hash_match_in_functions: %x - %x' % (src_function_address, target_function_address))

        src_function = self.binaries[0].get_function(src_function_address)
        target_function = self.binaries[1].get_function(target_function_address)
        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])

        matches = []
        for match_data in diff_algorithms.do_blocks_instruction_hash_match(src_function.get_basic_blocks(), target_function.get_basic_blocks()):
            if self.debug_level > 0:
                print('\t%x - %x : %d%%' % (match_data.source, match_data.target, match_data.match_rate))
            matches.append({'source': match_data.source, 'target': match_data.target, 'match_rate': match_data.match_rate})

        return matches

    def test_do_instruction_hash_match_in_functions(self):
        instruction_matches = self.do_instruction_hash_match_in_functions(0x6C83948B, 0x004496D9)

        if self.write_data:
            with open(r'current\instruction_matches_6C83948B_004496D9.json', 'w') as fd:
                json.dump(instruction_matches, fd, indent = 4)

        with open(r'expected\instruction_matches_6C83948B_004496D9.json', 'r') as fd:
            expected_instruction_matches = json.load(fd)        

        self.assertEqual(expected_instruction_matches, instruction_matches)

    def print_match_data_combination(self, match_data_combination, prefix = ''):
        print(prefix + '* print_match_data_combination: count: %d match_rate: %d%%' % (match_data_combination.count(), match_data_combination.get_match_rate()))
        for i in range(0, match_data_combination.count(), 1):
            match_data = match_data_combination.get(i)
            print(prefix + '\t%x - %x : %d%%' % (match_data.source, match_data.target, match_data.match_rate))

    def perform_multilevel_control_flow_matches(self, source, target):
        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
        
        address_pair = pybinkit.AddressPair(source, target)
        match_data_combinations = diff_algorithms.do_control_flow_matches((address_pair,), CREF_FROM)

        for match_data_combination in match_data_combinations:
            self.print_match_data_combination(match_data_combination)

            address_str_list = []
            address_pairs = match_data_combination.get_address_pairs()
            for address_pair in address_pairs:
                address_str_list.append('%x - %x' % (address_pair.source, address_pair.target))

            print('\tControl Flow Match:' + ','.join(address_str_list))
            sub_match_data_combinations = diff_algorithms.do_control_flow_matches(address_pairs, CREF_FROM)
            for sub_match_data_combination in sub_match_data_combinations:
                self.print_match_data_combination(sub_match_data_combination)

    def test_perform_multilevel_control_flow_matches(self):
        self.perform_multilevel_control_flow_matches(0x6c83a795, 0x44a9e3)
        self.perform_multilevel_control_flow_matches(0x6c81ac85, 0x42aeb8)
        self.perform_multilevel_control_flow_matches(0x6c8395e3, 0x00449831)

    def check_function_match(self, src_function_address, target_function_address, src_binary, target_binary, function_matches):
        for function_match in function_matches.get_matches():
            function_match.source
            function_match.target

        for match in function_match.match_data_list:
            match.source, match.target

        child_matches = diff_algorithms.do_control_flow_match(match.source, match.target, CREF_FROM)
        for child_match in child_matches:
            if self.debug_level > 0:
                print('\t\t%d: %x - %x vs %x - match_rate: %d' % (control_flow_type, child_match.type, child_match.source, child_match.target, child_match.match_rate))


    def do_function_instruction_hash_match(self, function_matches, filename_prefix = 'do_function_instruction_hash_match', sequence = 0):
        print('* do_function_instruction_hash_match:')
        function_matches.do_instruction_hash_match()
        matches = self.util.get_function_match_list(function_matches)
        unidentified_blocks = self.util.get_function_unidentified_blocks(function_matches)

        matches_filename = r'%s-%.8d-matches.json' % (filename_prefix, sequence)
        unidentified_blocks_filename = r'%s-%.8d-unidentified_blocks.json' % (filename_prefix, sequence)

        if self.write_data:
            with open(os.path.join(self.current_data_directory, matches_filename), 'w') as fd:
                json.dump(matches, fd, indent = 4)

            with open(os.path.join(self.current_data_directory, unidentified_blocks_filename), 'w') as fd:
                json.dump(unidentified_blocks, fd, indent = 4)

        with open(os.path.join(self.expected_data_directory, matches_filename), 'r') as fd:
            expected_matches = json.load(fd)

        with open(os.path.join(self.expected_data_directory, unidentified_blocks_filename), 'r') as fd:
            expected_unidentified_blocks = json.load(fd)

        self.assertTrue(self.util.compare_function_matches(expected_matches, matches))
        self.assertEqual(expected_unidentified_blocks, unidentified_blocks)

    def do_function_control_flow_match(self, function_matches, source_function_address = 0, filename_prefix = 'do_function_control_flow_match', sequence = 0, verify_results = True, rollback = False):
        print('* do_function_control_flow_match:')
        match_sequence = function_matches.do_control_flow_match(source_function_address)
        matches = self.util.get_function_match_list(function_matches, source_function_address)
        unidentified_blocks = self.util.get_function_unidentified_blocks(function_matches, source_function_address)

        matches_filename = r'%s-%.8x-%.8d-matches.json' % (filename_prefix, source_function_address, sequence)
        unidentified_blocks_filename = r'%s-%.8x-%.8d-unidentified_blocks.json' % (filename_prefix, source_function_address, sequence)

        if self.write_data:
            with open(os.path.join(self.current_data_directory, matches_filename), 'w') as fd:
                json.dump(matches, fd, indent = 4)

            with open(os.path.join(self.current_data_directory, unidentified_blocks_filename), 'w') as fd:
                json.dump(unidentified_blocks, fd, indent = 4)

        if rollback:
            print('\tremove_matches: match_sequence: %d' % match_sequence)
            function_matches.remove_matches(match_sequence)
            matches_removed = self.util.get_function_match_list(function_matches, source_function_address)
            if self.write_data:
                with open(os.path.join(self.current_data_directory, r'%s-%.8x-%.8d-matches_removed.json' % (filename_prefix, source_function_address, sequence)), 'w') as fd:
                    json.dump(matches_removed, fd, indent = 4)

        if verify_results:
            with open(os.path.join(self.expected_data_directory, matches_filename), 'r') as fd:
                expected_matches = json.load(fd)

            with open(os.path.join(self.expected_data_directory, unidentified_blocks_filename), 'r') as fd:
                expected_unidentified_blocks = json.load(fd)

            self.assertTrue(self.util.compare_function_matches(expected_matches, matches))
            self.assertEqual(str(expected_unidentified_blocks), str(unidentified_blocks))

    def do_instruction_hash_match(self, filename_prefix = 'do_instruction_hash_match', sequence = 0):
        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
        matches = diff_algorithms.do_instruction_hash_match()

        function_matches = pybinkit.FunctionMatches(self.binaries[0], self.binaries[1])
        function_matches.add_matches(matches)
        matches = self.util.get_function_match_list(function_matches)

        matches_filename = r'%s-%.8d-matches.json' % (filename_prefix, sequence)

        if self.write_data:            
            with open(os.path.join(self.current_data_directory, matches_filename), 'w') as fd:
                json.dump(matches, fd, indent = 4)

        with open(os.path.join(self.expected_data_directory, matches_filename), 'r') as fd:
            expected_matches = json.load(fd)

        self.assertTrue(self.util.compare_function_matches(expected_matches, matches))
        return function_matches

    def test_function_match(self, generate_test_case_files = False):
        function_matches = self.do_instruction_hash_match()
        self.do_function_instruction_hash_match(function_matches)
        self.do_function_control_flow_match(function_matches, 0x6c7fc779, rollback = True)
        
        if generate_test_case_files:
            for sequence in range(0, 20, 1):
                self.do_function_control_flow_match(function_matches, sequence = sequence, verify_results = False)

        for sequence in range(0, 5, 1):
            self.do_function_control_flow_match(function_matches, sequence = sequence)

    def do_function_diff(self, source, target):
        print('* do_function_diff:')
        function_diff_list = []
        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
        matches = diff_algorithms.do_function_instruction_hash_match(self.binaries[0].get_function(source), self.binaries[1].get_function(target))
        function_matches = pybinkit.FunctionMatches(self.binaries[0], self.binaries[1])
        function_matches.add_matches(matches)

        self.debug_level = 1
        self.util.get_match_list(matches)

        print('* do_instruction_hash_match:')
        function_matches.do_instruction_hash_match()
        function_matches_list = self.util.get_function_match_list(function_matches)
        unidentified_blocks = self.util.get_function_unidentified_blocks(function_matches)
        function_diff_list.append({'function_matches': function_matches_list, 'unidentified_blocks': unidentified_blocks})

        print('* do_control_flow_match:')
        function_matches.do_control_flow_match()
        function_matches_list = self.util.get_function_match_list(function_matches)        
        unidentified_blocks = self.util.get_function_unidentified_blocks(function_matches)
        function_diff_list.append({'function_matches': function_matches_list, 'unidentified_blocks': unidentified_blocks})

        return function_diff_list

    def do_function_pair_diff(self, src, target):
        function_diff_list = self.do_function_diff(src, target)

        filename = 'function_diff_%.8x_%.8x.json' % (src, target)
        if self.write_data:
            with open(filename, 'w') as fd:
                json.dump(function_diff_list, fd, indent = 4)

        with open(r'expected\%s' % filename, 'r') as fd:
            expected_function_diff_list = json.load(fd)

        self.assertEqual(expected_function_diff_list, function_diff_list)

    def test_function_pair_diffs(self):
        self.do_function_pair_diff(0x6c822ee8, 0x43313a)
        self.do_function_pair_diff(0x6c7fc779, 0x40c78a)

if __name__ == '__main__':
    unittest.main()
