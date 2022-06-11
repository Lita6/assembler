@echo off

pushd ..\build

cl -MT -nologo -Gm- -GR- -EHa- -Od -Oi -WX -Wall -wd4191 -wd4668 -wd4820 -wd4201 -FC -Z7 -GS- -Gs2000000000 ..\code\win32_assembler.cpp /link kernel32.lib -incremental:no -opt:ref -nodefaultlib -subsystem:windows -STACK:0x100000,0x100000

popd