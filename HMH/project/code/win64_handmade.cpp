#include <windows.h>

int __stdcall
WinMainCRTStartup
(void)
{
	
	OutputDebugStringA("This is the first thing we have printed.\n");
	
	return(0);
}