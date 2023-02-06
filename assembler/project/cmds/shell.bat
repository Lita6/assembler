@echo off

cd project\code
copy ..\cmds\assembler_build.bat build.bat
call ..\cmds\4coder
call ..\cmds\rdbg
call ..\cmds\testrdbg
cls