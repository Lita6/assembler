@echo off

pushd ..\build

cl -MT -nologo -Gm- -GR- -EHa- -Od -Oi -WX -wd4201 -FC -Z7 -GS- -Gs2000000000 ..\code\win32_assembler.cpp /link -incremental:no -opt:ref -nodefaultlib -subsystem:windows kernel32.lib -STACK:0x100000,0x100000

popd