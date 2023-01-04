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
	
	Buffer strings = win64_make_buffer(PAGE, PAGE_READWRITE);
	Buffer reserved = win64_make_buffer(PAGE, PAGE_READWRITE);
	init(&reserved, &strings);
	
	Buffer byte_code = win64_make_buffer(PAGE, PAGE_EXECUTE_READWRITE);
	Buffer file = win64_make_buffer(PAGE, PAGE_READWRITE);
	
	{
		String src = create_string(&file, "ret");
		assemble(&byte_code, src);
		fn_void_to_void test = (fn_void_to_void)byte_code.memory;
		test();
		Assert(*byte_code.memory == 0xc3);
		
		clear_buffer(&file);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "155 -> eax\r\nret");
		assemble(&byte_code, src);
		fn_void_to_u32 test = (fn_void_to_u32)byte_code.memory;
		u32 result = test();
		Assert(result == 155);
		
		clear_buffer(&file);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "0 -> eax\r\nret");
		assemble(&byte_code, src);
		fn_void_to_u32 test = (fn_void_to_u32)byte_code.memory;
		u32 result = test();
		Assert(result == 0);
		
		clear_buffer(&file);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "eax <- 42\r\nret");
		assemble(&byte_code, src);
		fn_void_to_u32 test = (fn_void_to_u32)byte_code.memory;
		u32 result = test();
		Assert(result == 42);
		
		clear_buffer(&file);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "89 -> ecx\r\n0 -> eax\r\nret");
		assemble(&byte_code, src);
		fn_void_to_u32 test = (fn_void_to_u32)byte_code.memory;
		u32 result = test();
		Assert(result == 0);
		
		clear_buffer(&file);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "89 -> r8d\r\n0 -> eax\r\nret");
		assemble(&byte_code, src);
		fn_void_to_u32 test = (fn_void_to_u32)byte_code.memory;
		u32 result = test();
		Assert(result == 0);
		
		clear_buffer(&file);
		clear_buffer(&byte_code);
	}
	
	return(0);
}