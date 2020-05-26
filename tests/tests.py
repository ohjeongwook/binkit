import pybinkit

# CALL, CREF_FROM, CREF_TO, DREF_FROM, DREF_TO, CALLED

def dump_basic_blocks(basic_blocks):
    for basic_block_address in basic_blocks.get_addresses():
        symbol = basic_blocks.get_symbol(basic_block_address)
        if symbol:
            print('%.8x: %s' % (basic_block_address, symbol))
        else:
            print('%.8x:' % (basic_block_address))

        print('\t'+basic_blocks.get_instruction_hash(basic_block_address))

        for ref_type in range(0, 6, 1):
            for reference in basic_blocks.get_code_references(basic_block_address, ref_type):
                print('\t- [%d] -> %.8x' % (ref_type, reference))

        for parent in basic_blocks.get_parents(basic_block_address):
            print('\tparent: %.8x' % (parent))

binary = pybinkit.Binary()
binary.open(r'examples\EPSIMP32-2006.1200.4518.1014.db', 0)
basic_blocks = binary.get_basic_blocks()
dump_basic_blocks(basic_blocks)

binary2 = pybinkit.Binary()
binary2.open(r'examples\EPSIMP32-2006.1200.6731.5000.db', 0)
basic_blocks2 = binary2.get_basic_blocks()
dump_basic_blocks(basic_blocks2)

for call_target in basic_blocks2.get_call_targets():
    print('call_target: %x' % call_target)


functions2 = binary2.get_functions()
for function_address in functions2.get_addresses():
    symbol = basic_blocks2.get_symbol(function_address)
    print('function_address: %x - %s' % (function_address, symbol))
    for basic_block_address in functions2.get_function_basic_blocks(function_address):
        print('\t%x' % (basic_block_address))
