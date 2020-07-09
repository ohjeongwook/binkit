import time
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
            binary.open(filename)
            self.binaries.append(binary)


    def print_match_data_combination(self, match_data_combination, prefix = ''):
        print(prefix + '* print_match_data_combination: count: %d match_rate: %d%%' % (match_data_combination.count(), match_data_combination.get_match_rate()))
        for i in range(0, match_data_combination.count(), 1):
            match_data = match_data_combination.get(i)
            print(prefix + '\t%x - %x : %d%%' % (match_data.source, match_data.target, match_data.match_rate))

    def print_match_data_combinations(self, match_data_combinations, prefix = ''):
        for match_data_combination in match_data_combinations:
            self.print_match_data_combination(match_data_combination, prefix + '\t')

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
            self.print_match_data_combinations(sub_match_data_combinations, '\t')

    def do_function_match(self):
        print('* do_function_match:')

        diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
        matches = diff_algorithms.do_instruction_hash_match()

        function_matches = pybinkit.FunctionMatches(self.binaries[0], self.binaries[1])
        function_matches.add_matches(matches)

        for function_match in function_matches.get_matches():
            print('%x - %x (size: %d)' % (function_match.source, function_match.target, len(function_match.match_data_list)))

            match_data_combinations = diff_algorithms.get_match_data_combinations(function_match.match_data_list)
            self.print_match_data_combinations(match_data_combinations, '\t')

        print('')
        print('='*80)
        function_matches.do_instruction_hash_match()

        for function_match in function_matches.get_matches():
            print('%x - %x (size: %d)' % (function_match.source, function_match.target, len(function_match.match_data_list)))

            #start_time = time.time()
            #match_data_combinations = diff_algorithms.get_match_data_combinations(function_match.match_data_list)
            #self.print_match_data_combinations(match_data_combinations, '\t')
            #end_time = time.time()
            #print("--- %s seconds ---" % (end_time - start_time))

if __name__ == '__main__':
    filenames = [r'examples\EPSIMP32-2006.1200.4518.1014.db', r'examples\EPSIMP32-2006.1200.6731.5000.db']
    tests = Tests(filenames)
    #tests.dump()
    #tests.do_instruction_hash_match()
    #tests.perform_multilevel_control_flow_matches(0x6c83a795, 0x44a9e3)
    #tests.perform_multilevel_control_flow_matches(0x6c81ac85, 0x42aeb8)
    #tests.perform_multilevel_control_flow_matches(0x6c8395e3, 0x00449831)
    #tests.do_function_match()
    tests.dump_functions()
    