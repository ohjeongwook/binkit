copy /y ..\x64\Debug\*.pyd . 
python tests.py TestCase.test_do_instruction_hash_match_in_functions > test_do_instruction_hash_match_in_functions.log
pause