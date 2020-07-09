import unittest
import pybinkit
import json

CALL = 0
CREF_FROM = 1
CREF_TO = 2
DREF_FROM = 3
DREF_TO = 4
CALLED = 5

class TestingClass(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestingClass, self).__init__(*args, **kwargs)

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
        functions = binary.get_functions()
        basic_blocks = binary.get_basic_blocks()
        for function_address in functions.get_addresses():
            function_data = {'address': function_address}
            symbol = basic_blocks.get_symbol(function_address)
            function_data['symbol'] = symbol
            function_data['basic_block_addresses'] = []

            if self.debug_level > 0:
                print('%.8x' % function_address)
                print('function_address: %x - %s' % (function_address, symbol))

            for basic_block_address in functions.get_basic_blocks(function_address):
                if self.debug_level > 0:
                    print('\t%x' % (basic_block_address))

                function_data['basic_block_addresses'].append(basic_block_address)
            function_data_list.append(function_data)

        return function_data_list

    def test_dump_functions(self):
        function_data_list_arrary = []
        for binary in self.binaries:
            function_data_list_arrary.append(self.dump_functions(binary))

        if self.write_data:
            with open('function_data_list_arrary.json', 'w') as fd:
                json.dump(function_data_list_arrary, fd, indent = 4)        

        with open(r'expected\function_data_list_arrary.json', 'r') as fd:
            expected_function_data_list_arrary = json.load(fd)

        self.assertEqual(expected_function_data_list_arrary, function_data_list_arrary)

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

if __name__ == '__main__':
    unittest.main()