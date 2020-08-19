import os
import sys
import json
import pprint
import traceback
import unittest
import pybinkit
from util import *

CALL = 0
CREF_FROM = 1
CREF_TO = 2
DREF_FROM = 3
DREF_TO = 4
CALLED = 5

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

    def assert_true(self, obj):
        try:
            self.assertTrue(obj)
        except:
            traceback.print_exc()

    def assert_equal(self, obj1, obj2):
        try:
            self.assertEqual(obj1, obj2)
        except:
            traceback.print_exc()

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
                if symbol :
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
        current_basic_block_data_list_pair = []
        for binary in self.binaries:
            basic_blocks = binary.get_basic_blocks()
            current_basic_block_data_list_pair.append(self.dump_basic_blocks(basic_blocks))

        if self.write_data:
            with open(r'current\basic_block_data_list_pair.json', 'w') as fd:
                json.dump(current_basic_block_data_list_pair, fd, indent = 4)

        with open(r'expected\basic_block_data_list_pair.json', 'r') as fd:
            expected_basic_block_data_list_pair = json.load(fd)

        self.assert_equal(expected_basic_block_data_list_pair, current_basic_block_data_list_pair)

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

    def get_address_to_function_data_map(self, function_data_list):
        address_to_function_data_map = {}
        for function_data in function_data_list:
            address_to_function_data_map[function_data['address']] = function_data
        return address_to_function_data_map

    def compare_function_list(self, expected_function_data_list, current_function_data_list):
        expected_address_to_function_data_map = self.get_address_to_function_data_map(expected_function_data_list)
        current_address_to_function_data_map = self.get_address_to_function_data_map(current_function_data_list)

        for address, function_data in expected_address_to_function_data_map.items():
            if not address in current_address_to_function_data_map:
                print(f"Missing address in current_address_to_function_data_map: %d" % address)
            self.assert_true(address in current_address_to_function_data_map)
            self.assert_equal(expected_address_to_function_data_map[address], current_address_to_function_data_map[address])

        for address, function_data in current_address_to_function_data_map.items():
            if not address in expected_address_to_function_data_map:
                print(f"Missing address in expected_address_to_function_data_map: %d" % address)
            self.assert_true(address in expected_address_to_function_data_map)
            self.assert_equal(expected_address_to_function_data_map[address], current_address_to_function_data_map[address])            

    def test_dump_functions(self):
        current_function_data_list_pair = []
        for binary in self.binaries:
            current_function_data_list_pair.append(self.dump_functions(binary))

        if self.write_data:
            with open(r'current\function_data_list_pair.json', 'w') as fd:
                json.dump(current_function_data_list_pair, fd, indent = 4)

        with open(r'expected\function_data_list_pair.json', 'r') as fd:
            expected_function_data_list_pair = json.load(fd)

        for i in range(0, len(expected_function_data_list_pair), 1):
            self.compare_function_list(expected_function_data_list_pair[i], current_function_data_list_pair[i])

    def sort_match_data_list(self, match_data_list):
        match_data_map = {}
        for match_data in match_data_list:
            match_data_map[match_data['source']] = match_data

        sorted_match_data_list = []
        source_addresses = list(match_data_map.keys())
        source_addresses.sort()
        for source_address in source_addresses:
            sorted_match_data_list.append(match_data_map[source_address])

        return sorted_match_data_list

    def test_instruction_hash_match(self):
        if self.debug_level > 0:
            print('* test_instruction_hash_match:')

        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
        matches = diff_algorithms.do_instruction_hash_match()

        current_match_data_list = []
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

            current_match_data_list.append(match_data)

        current_match_data_list = self.sort_match_data_list(current_match_data_list)
        if self.write_data:
            with open(r'current\instruction_hash_match_data_list.json', 'w') as fd:
                json.dump(current_match_data_list, fd, indent = 4)

        with open(r'expected\instruction_hash_match_data_list.json', 'r') as fd:
            expected_match_data_list = json.load(fd)

        self.assert_equal(expected_match_data_list, current_match_data_list)

    def do_instruction_hash_match_in_functions(self, source_function_address, target_function_address):
        if self.debug_level > 0:
            print('* do_instruction_hash_match_in_functions: %x - %x' % (source_function_address, target_function_address))

        src_function = self.binaries[0].get_function(source_function_address)
        target_function = self.binaries[1].get_function(target_function_address)
        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])

        matches = []
        for match_data in diff_algorithms.do_blocks_instruction_hash_match(src_function.get_basic_blocks(), target_function.get_basic_blocks()):
            if self.debug_level > 0:
                print('\t%x - %x : %d%%' % (match_data.source, match_data.target, match_data.match_rate))
            matches.append({'source': match_data.source, 'target': match_data.target, 'match_rate': match_data.match_rate})

        return matches

    def test_do_instruction_hash_match_in_functions(self):
        source_function_address -= 0x6C83948B - self.binaries[0].get_image_base()
        target_function_address -= 0x004496D9 - self.binaries[1].get_image_base()
        instruction_matches = self.do_instruction_hash_match_in_functions(source_function_address, target_function_address)

        if self.write_data:
            with open(r'current\instruction_matches_6C83948B_004496D9.json', 'w') as fd:
                json.dump(instruction_matches, fd, indent = 4)

        with open(r'expected\instruction_matches_6C83948B_004496D9.json', 'r') as fd:
            expected_instruction_matches = json.load(fd)        

        self.assert_equal(expected_instruction_matches, instruction_matches)

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
        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])

        for function_match in function_matches.get_matches():
            function_match.source
            function_match.target

        for match in function_match.match_data_list:
            match.source, match.target

        child_matches = diff_algorithms.do_control_flow_match(match.source, match.target, CREF_FROM)
        for child_match in child_matches:
            if self.debug_level > 0:
                print('\t\t%d: %x - %x vs %x - match_rate: %d' % (control_flow_type, child_match.type, child_match.source, child_match.target, child_match.match_rate))

    def compare_function_matches(self, current_matches, matches_filename):
        current_function_match_tool = FunctionMatchTool(function_matches = current_matches, binaries = self.binaries)
        current_function_match_tool.sort()
        if self.write_data:            
            current_function_match_tool.write(os.path.join(self.current_data_directory, matches_filename))

        expected_function_match_tool = FunctionMatchTool(os.path.join(self.expected_data_directory, matches_filename), binaries = self.binaries)
        expected_function_match_tool.sort()
        self.assert_true(self.util.compare_function_matches(expected_function_match_tool.match_results['function_matches'], current_function_match_tool.match_results['function_matches']))

    def _test_function_instruction_hash_match(self, function_matches, source_function_address = 0, filename_prefix = 'test_function_instruction_hash_match', sequence = 0):
        function_matches.do_instruction_hash_match()
        self.compare_function_matches(self.util.get_function_match_list(function_matches), r'%s-%.8x-%.8d.json' % (filename_prefix, self.binaries[0].get_image_base() + source_function_address, sequence))

    def _test_function_control_flow_match(self, function_matches, source_function_address = 0, filename_prefix = 'test_function_control_flow_match', sequence = 0, verify_results = True, rollback = False):
        match_sequence = function_matches.do_control_flow_match(source_function_address)
        if verify_results:
            self.compare_function_matches(self.util.get_function_match_list(function_matches, source_function_address), r'%s-%.8x-%.8d.json' % (filename_prefix, self.binaries[0].get_image_base() + source_function_address, sequence))

        """
        if rollback:
            print('\tremove_matches: match_sequence: %d' % match_sequence)
            function_matches.remove_matches(match_sequence)
            matches_removed = self.util.get_function_match_list(function_matches, source_function_address)
            if self.write_data:
                with open(os.path.join(self.current_data_directory, r'%s-%.8x-%.8d_removed.json' % (filename_prefix, source_function_address, sequence)), 'w') as fd:
                    json.dump(matches_removed, fd, indent = 4)
        """

    def _test_instruction_hash_match(self, filename_prefix = 'test_instruction_hash_match', sequence = 0):
        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
        current_matches = diff_algorithms.do_instruction_hash_match()
        function_matches = pybinkit.FunctionMatches(self.binaries[0], self.binaries[1])
        function_matches.add_matches(current_matches)
        current_matches = self.util.get_function_match_list(function_matches)
        return function_matches

    def test_function_match(self):
        function_matches = self._test_instruction_hash_match()
        self._test_function_instruction_hash_match(function_matches)
        self._test_function_control_flow_match(function_matches, 0x6c7fc779 - self.binaries[0].get_image_base(), rollback = True)
        for sequence in range(0, 5, 1):
            try:
                self._test_function_control_flow_match(function_matches, sequence = sequence)
            except:
                traceback.print_exc()

    def do_function_instruction_hash_match(self, source_function_address, target_function_address, filename_prefix = 'do_function_instruction_hash_match', sequence = 0):
        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
        matches = diff_algorithms.do_function_instruction_hash_match(self.binaries[0].get_function(int(source_function_address)), self.binaries[1].get_function(int(target_function_address)))
        function_matches = pybinkit.FunctionMatches(self.binaries[0], self.binaries[1])
        function_matches.add_matches(matches)
        self.compare_function_matches(self.util.get_function_match_list(function_matches), r'%s-%.8x-%.8d.json' % (filename_prefix, self.binaries[0].get_image_base() + source_function_address, sequence))
        return function_matches

    def _test_function_match(self, source_function_address, target_function_address):
        source_function_address -= self.binaries[0].get_image_base()
        target_function_address -= self.binaries[1].get_image_base()
        function_matches = self.do_function_instruction_hash_match(source_function_address, target_function_address, filename_prefix = 'test_function_match', sequence = 0)
        self._test_function_instruction_hash_match(function_matches, source_function_address, filename_prefix = 'test_function_match',sequence = 1)
        self._test_function_control_flow_match(function_matches, source_function_address, filename_prefix = 'test_function_match',sequence = 2)
        self._test_function_control_flow_match(function_matches, source_function_address, filename_prefix = 'test_function_match',sequence = 3)

    def test_function_matches(self):
        self._test_function_match(0x6c822ee8, 0x43313a)
        self._test_function_match(0x6c7fc779, 0x40c78a)
        self._test_function_match(0x6C7FCCF4, 0x40CCCF)

if __name__ == '__main__':
    unittest.main()
