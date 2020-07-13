copy /y ..\x64\Debug\*.pyd . 
python tests.py TestCase.test_function_pair_diffs
pause