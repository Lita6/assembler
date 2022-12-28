#include <windows.h>

#include "assembler.cpp"

global u32 PAGE;

int __stdcall
WinMainCRTStartup
(void)
{
	
	SYSTEM_INFO SysInfo = {};
	GetSystemInfo(&SysInfo);
	Assert(SysInfo.dwPageSize != 0);
	PAGE = SysInfo.dwPageSize;
	
	// TODO: GetCommandLine for the file to assemble
	
	read_file_result src = Win64ReadEntireFile("d:\\programming\\github\\assembler\\game\\game.laf");
	(void)src;
	
	return(0);
}