copy /y ..\x64\Debug\*.pyd . 
python tests.py TestCase.test_instruction_hash_match > test_instruction_hash_match.log
pause