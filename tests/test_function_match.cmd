copy /y ..\src\x64\Debug\*.pyd . 
python tests.py TestCase.test_function_match > test_function_match.log
pause