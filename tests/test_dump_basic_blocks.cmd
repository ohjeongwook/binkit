copy /y ..\x64\Debug\*.pyd . 
python tests.py TestCase.test_dump_basic_blocks > test_dump_basic_blocks.log
pause