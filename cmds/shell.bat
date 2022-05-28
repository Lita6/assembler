@echo off

call "c:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
PATH=d:\programming\github\assembler\cmds;%PATH%

cd code
call 4coder
call vs
cls