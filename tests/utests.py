import unittest
import pybinkit
import json

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
        filenames = [r'examples\EPSIMP32-2006.1200.4518.1014.db', r'examples\EPSIMP32-2006.1200.6731.5000.db']
        self.binaries = []
        for filename in filenames:
            binary = pybinkit.Binary()
            if self.debug_level > 0:
                print('Opening %s...' % filename)
            binary.open(filename)
            self.binaries.append(binary)

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
        basic_block_data_list_array = []
        for binary in self.binaries:
            basic_blocks = binary.get_basic_blocks()
            basic_block_data_list = self.dump_basic_blocks(basic_blocks)
            basic_block_data_list_array.append(basic_block_data_list)

        if self.write_data:
            with open('basic_block_data_list_array.json', 'w') as fd:
                json.dump(basic_block_data_list_array, fd, indent = 4)

        with open(r'expected\basic_block_data_list_array.json', 'r') as fd:
            expected_basic_block_data_list_array = json.load(fd)

        self.assertEqual(expected_basic_block_data_list_array, basic_block_data_list_array)

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
        function_data_list_array = []
        for binary in self.binaries:
            function_data_list_array.append(self.dump_functions(binary))

        if self.write_data:
            with open('function_data_list_array.json', 'w') as fd:
                json.dump(function_data_list_array, fd, indent = 4)

        with open(r'expected\function_data_list_array.json', 'r') as fd:
            expected_function_data_list_array = json.load(fd)

            for expected_function_data_list in expected_function_data_list_array:
                for expected_function_data in expected_function_data_list:
                    expected_function_data['basic_block_addresses'].sort()

        with open(r'expected\function_data_list_array.json', 'w') as fd:
            json.dump(expected_function_data_list_array, fd, indent = 4)

        self.assertEqual(expected_function_data_list_array, function_data_list_array)

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
            with open('match_data_list.json', 'w') as fd:
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
        for match_data in diff_algorithms.do_instruction_hash_match_in_blocks(src_function.get_basic_blocks(), target_function.get_basic_blocks()):
            if self.debug_level > 0:
                print('\t%x - %x : %d%%' % (match_data.source, match_data.target, match_data.match_rate))
            matches.append({'source': match_data.source, 'target': match_data.target, 'match_rate': match_data.match_rate})

        return matches

    def test_do_instruction_hash_match_in_functions(self):
        instruction_matches = self.do_instruction_hash_match_in_functions(0x6C83948B, 0x004496D9)

        if self.write_data:
            with open('instruction_matches_6C83948B_004496D9.json', 'w') as fd:
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
        print('* perform_multilevel_control_flow_matches: %x - %x' % (source, target))
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


    def get_match_list(self, matches):
        match_data_list = []
        for match in matches:
            match_data = {'source': match.source, 'target': match.target, 'match_rate': match.match_rate}
            match_data_list.append(match_data)
        return match_data_list

    def get_function_match_list(self, function_matches):
        function_match_data_list = []
        for function_match in function_matches.get_matches():
            print('%x - %x (size: %d)' % (function_match.source, function_match.target, len(function_match.match_data_list)))
            function_match_data = {'source': function_match.source, 'target': function_match.target}
            function_match_data['matches'] = self.get_match_list(function_match.match_data_list)
            function_match_data_list.append(function_match_data)

            #match_data_combinations = diff_algorithms.get_match_data_combinations(function_match.match_data_list)
            #self.print_match_data_combinations(match_data_combinations, '\t')

        return function_match_data_list

    def test_function_match(self):
        print('* do_function_match:')

        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
        basic_block_matches = diff_algorithms.do_instruction_hash_match()

        function_matches = pybinkit.FunctionMatches(self.binaries[0], self.binaries[1])
        function_matches.add_matches(basic_block_matches)
        original_function_matches = self.get_function_match_list(function_matches)

        function_matches.do_instruction_hash_match()
        revised_function_matches = self.get_function_match_list(function_matches)

        if self.write_data:
            with open('original_function_matches.json', 'w') as fd:
                json.dump(original_function_matches, fd, indent = 4)

            with open('revised_function_matches.json', 'w') as fd:
                json.dump(revised_function_matches, fd, indent = 4)                

        with open(r'expected\original_function_matches.json', 'r') as fd:
            expected_original_function_matches = json.load(fd)

        with open(r'expected\revised_function_matches.json', 'r') as fd:
            expected_revised_function_matches = json.load(fd)            

        self.assertEqual(expected_original_function_matches, original_function_matches)
        self.assertEqual(expected_revised_function_matches, revised_function_matches)

if __name__ == '__main__':
    unittest.main()
