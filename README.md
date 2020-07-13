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

### do_blocks_instruction_hash_match

```
diff_algorithms.do_blocks_instruction_hash_match(source_basic_block_addresses, target_basic_block_addresses):
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

## binkit IDA Plugin

* You can run following IDAPython script to download and install binkit IDA Plugin
   - [Download](Scripts/install_binkit_plugin.py)

```
import os
import urllib2
plugins_folder = os.path.join(idaapi.get_user_idadir(), "plugins")
if not os.path.isdir(plugins_folder):
    os.makedirs(plugins_folder)
for filename in ('binkit.dll', 'binkit64.dll'):
   url = 'https://github.com/ohjeongwook/binkit/releases/download/v0.1/' + filename
   local_filename = os.path.join(plugins_folder, filename)
   print('Downloading %s -> %s' % (url, local_filename))
   response = urllib2.urlopen(url)
   with open(local_filename, 'wb') as fd:
      fd.write(response.read())
```
