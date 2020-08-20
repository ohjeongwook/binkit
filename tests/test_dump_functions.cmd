copy /y ..\src\x64\Debug\*.pyd . 
python tests.py TestCase.test_dump_functions > test_dump_functions.log
pause