copy /y ..\x64\Debug\*.pyd . 
python tests.py TestCase.test_function_match
pause