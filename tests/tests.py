import pybinkit

class Tests:
    def __init__(self, filenames):
        self.binaries = []
        for filename in filenames:
            binary = pybinkit.Binary()
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
        diff_alrogithms = pybinkit.DiffAlgorithms()
        basic_block0 = self.binaries[0].get_basic_blocks()
        basic_block1 = self.binaries[1].get_basic_blocks()
        matches = diff_alrogithms.do_instruction_hash_match(basic_block0, basic_block1)
        for match in matches:
            print('%x - %x vs %s - match_rate: %d' % (match.type, match.original_address, match.patched_address, match.type))

if __name__ == '__main__':
    filenames = [r'examples\EPSIMP32-2006.1200.4518.1014.db', r'examples\EPSIMP32-2006.1200.6731.5000.db']
    tests = Tests(filenames)
    #tests.dump()
    tests.do_instruction_hash_match()
