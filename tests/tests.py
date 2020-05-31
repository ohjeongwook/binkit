import pybinkit

CALL = 0
CREF_FROM = 1
CREF_TO = 2
DREF_FROM = 3
DREF_TO = 4
CALLED = 5

class Tests:
    def __init__(self, filenames):
        self.binaries = []
        for filename in filenames:
            binary = pybinkit.Binary()
            print('Opening %s...' % filename)
            binary.open(filename, 0)
            self.binaries.append(binary)

    def dump_basic_blocks(self, basic_blocks):
        for basic_block_address in basic_blocks.get_addresses():
            symbol = basic_blocks.get_symbol(basic_block_address)
            if symbol:
                print('%.8x: %s' % (basic_block_address, symbol))
            else:
                print('%.8x:' % (basic_block_address))

            print('\t'+str(basic_blocks.get_instruction_hash(basic_block_address)))

            # CALL, CREF_FROM, CREF_TO, DREF_FROM, DREF_TO, CALLED
            for ref_type in range(0, 6, 1):
                for reference in basic_blocks.get_code_references(basic_block_address, ref_type):
                    print('\t- [%d] -> %.8x' % (ref_type, reference))

            for parent in basic_blocks.get_parents(basic_block_address):
                print('\tparent: %.8x' % (parent))

    def dump(self):
        for binary in self.binaries:
            basic_blocks = binary.get_basic_blocks()
            self.dump_basic_blocks(basic_blocks)

    def dump_call_targets(self, basic_blocks):
        for call_target in basic_blocks.get_call_targets():
            print('call_target: %x' % call_target)

    def dump_functions_addresses(self, functions, basic_blocks):
        for function_address in functions.get_addresses():
            symbol = basic_blocks.get_symbol(function_address)
            print('function_address: %x - %s' % (function_address, symbol))
            for basic_block_address in functions.get_function_basic_blocks(function_address):
                print('\t%x' % (basic_block_address))

    def dump_functions(self, binary):
        functions = binary.get_functions()
        basic_blocks = binary.get_functions()
        self.dump_functions_addresses(functions, basic_blocks)

    def do_instruction_hash_match(self):
        basic_block0 = self.binaries[0].get_basic_blocks()
        basic_block1 = self.binaries[1].get_basic_blocks()

        print('Loading DiffAlgorithms...')
        diff_algorithms = pybinkit.DiffAlgorithms(basic_block0, basic_block1)
        print('Performing instruction hash matches...')
        matches = diff_algorithms.do_instruction_hash_match()
        for match in matches:
            print('>> Match: %x vs %x - match_rate: %d' % (match.source, match.target, match.match_rate))

            print('\tPerforming do_control_flow_match:')
            for control_flow_type in (CREF_FROM, ) : #, CALL, DREF_FROM):
                child_matches = diff_algorithms.do_control_flow_match(match.source, match.target, control_flow_type)
                for child_match in child_matches:
                    print('\t\t%d: %x - %x vs %x - match_rate: %d' % (control_flow_type, child_match.type, child_match.source, child_match.target, child_match.match_rate))

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

    def print_match_data_combination(self, match_data_combination, prefix = ''):
        print(prefix + '* Match Data Combination: count: %d match_rate: %d%%' % (match_data_combination.count(), match_data_combination.get_match_rate()))
        for i in range(0, match_data_combination.count(), 1):
            match_data = match_data_combination.get(i)
            print(prefix + '\t%x - %x : %d%%' % (match_data.source, match_data.target, match_data.match_rate))

    def print_match_data_combinations(self, match_data_combinations, prefix = ''):
        for match_data_combination in match_data_combinations:
            self.print_match_data_combination(match_data_combination, prefix + '\t')

    def perform_multilevel_control_flow_matches(self, source, target):
        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0].get_basic_blocks(), self.binaries[1].get_basic_blocks())
        print('Control Flow Match: %x - %x' % (source, target))
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
            self.print_match_data_combinations(sub_match_data_combinations, '\t')

if __name__ == '__main__':
    filenames = [r'examples\EPSIMP32-2006.1200.4518.1014.db', r'examples\EPSIMP32-2006.1200.6731.5000.db']
    tests = Tests(filenames)
    #tests.dump()
    #tests.do_instruction_hash_match()
    #tests.perform_multilevel_control_flow_matches(0x6c83a795, 0x44a9e3)
    tests.perform_multilevel_control_flow_matches(0x6c81ac85, 0x42aeb8)
