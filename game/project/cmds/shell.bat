@echo off

cd project\code
copy d:\programming\github\assembler\assembler\build\win64_assembler.exe ..\..\build\win64_assembler.exe
call ..\cmds\4coder
call ..\cmds\rdbg
cls