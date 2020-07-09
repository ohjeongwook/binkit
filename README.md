# Building

Set PYTHONHOME variable to Python home directory. 

* For example:

```
setx PYTHONHOME C:\Users\Administrator\AppData\Local\Programs\Python\Python38
```

Open binkit.sln solution file to compile Loader and pybinkit project

* Use Visual Studio 2019

# Using pybinkit

* Import pybinkit

```
import pybinkit
```


## Binary

* Loading binary with 
   - filename
   - fieldID (optional): 0

```
binary = pybinkit.Binary()
binary.open(filename, 0)
```


## DiffAlgorithms

```
diff_algorithms = pybinkit.DiffAlgorithms(self.binaries[0], self.binaries[1])
```

### do_instruction_hash_match

```
diff_algorithms.do_instruction_hash_match()
```

### do_instruction_hash_match_in_blocks

```
diff_algorithms.do_instruction_hash_match_in_blocks(source_basic_block_addresses, target_basic_block_addresses):
```

### do_control_flow_match

```
child_matches = diff_algorithms.do_control_flow_match(match.source, match.target, control_flow_type)
```

### do_control_flow_matches

* control_flow_type:

   - CREF_FROM

```
match_data_combinations = diff_algorithms.do_control_flow_matches((address_pair,), control_flow_type)
```

### get_match_data_combinations

```
match_data_combinations = diff_algorithms.get_match_data_combinations(function_match.match_data_list)
```

## FunctionMatches

### add_matches

```
function_matches.add_matches(matches)
```

### do_instruction_hash_match


```
function_matches.do_instruction_hash_match()
```

### get_matches

```
for function_match in function_matches.get_matches():
   print('%x - %x (size: %d)' % (function_match.source, function_match.target, len(function_match.match_data_list)))
```