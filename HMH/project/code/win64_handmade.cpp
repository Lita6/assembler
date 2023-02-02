#include <windows.h>

typedef void (*fn)(char *);

int __stdcall
WinMainCRTStartup
(void)
{
	
	HMODULE kernel32 = LoadLibraryA("KERNEL32.dll");
	fn func = (fn)GetProcAddress(kernel32, "OutputDebugStringA");
	func("This is the first thing we have printed.\n");
	
	return(0);
}