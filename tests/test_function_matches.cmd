copy /y ..\x64\Debug\*.pyd . 
python tests.py TestCase.test_function_matches > test_function_matches.log
pause