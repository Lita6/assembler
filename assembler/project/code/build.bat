@echo off

pushd ..\..\build

cl -MT -nologo -Gm- -GR- -EHa- -Od -Oi -WX -Wall -wd4061 -wd4062 -wd5045 -wd4191 -wd4668 -wd4820 -wd4201 -FC -Z7 -GS- -Gs2000000000 ..\project\code\win64_assembler.cpp /link kernel32.lib gdi32.lib user32.lib winmm.lib -incremental:no -opt:ref -nodefaultlib -subsystem:windows -STACK:0x100000,0x100000

popd