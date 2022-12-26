@echo off

cd project\code
copy ..\cmds\test_build.bat build.bat
call ..\cmds\4coder
call ..\cmds\testrdbg
cls