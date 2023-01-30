#include <windows.h>

typedef void (*fn)(char *);

int __stdcall
WinMainCRTStartup
(void)
{
	
	HMODULE kernell32 = LoadLibraryA("KERNELL32.dll");
	fn func = (fn)GetProcAddress(kernell32, "OutputDebugStringA");
	func("This is the first thing we have printed.\n");
	
	return(0);
}