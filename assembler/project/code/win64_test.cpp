#include <windows.h>

#include "assembler.cpp"

global u32 PAGE;

void
loadProgram
(Buffer *bytes, Buffer program)
{
	U8_Array *header = (U8_Array *)(program.memory);
	
	for(u64 i = 0; i < header[0].len; i++)
	{
		buffer_append_u8(bytes, header[0].bytes[i]);
	}
	
	if(header[1].len != 0)
	{
		u32 size_of_code = (u32)(bytes->end - bytes->memory);
		u32 get_to_end_of_code = AlignSize(size_of_code, PAGE) - size_of_code;
		buffer_allocate(bytes, get_to_end_of_code);
		
		for(u64 i = 0; i < header[1].len; i++)
		{
			buffer_append_u8(bytes, header[1].bytes[i]);
		}
	}
	
}

int __stdcall
WinMainCRTStartup
(void)
{
	
	SYSTEM_INFO SysInfo = {};
	GetSystemInfo(&SysInfo);
	Assert(SysInfo.dwPageSize != 0);
	PAGE = SysInfo.dwPageSize;
	
	Buffer AssembleMemory = win64_make_buffer((2*PAGE), PAGE_READWRITE);
	
	Buffer byte_code = win64_make_buffer(2*PAGE, PAGE_EXECUTE_READWRITE);
	Buffer program = win64_make_buffer(PAGE, PAGE_READWRITE);
	Buffer file = win64_make_buffer(PAGE, PAGE_READWRITE);
	
	{
		String src = create_string(&file, "ret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		fn_void_to_void test = (fn_void_to_void)byte_code.memory;
		test();
		Assert(*byte_code.memory == 0xc3);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "155 -> eax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		fn_void_to_u32 test = (fn_void_to_u32)byte_code.memory;
		u32 result = test();
		Assert(result == 155);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "0 -> eax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		fn_void_to_u32 test = (fn_void_to_u32)byte_code.memory;
		u32 result = test();
		Assert(result == 0);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "eax <- 42\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		fn_void_to_u32 test = (fn_void_to_u32)byte_code.memory;
		u32 result = test();
		Assert(result == 42);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "89 -> ecx\r\necx -> eax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		fn_void_to_u32 test = (fn_void_to_u32)byte_code.memory;
		u32 result = test();
		Assert(result == 89);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "155 -> r8d\r\nr8d -> eax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		fn_void_to_u32 test = (fn_void_to_u32)byte_code.memory;
		u32 result = test();
		Assert(result == 155);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "155 -> r8\r\nr8 -> rax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 155);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "155 -> r8\r\nr8 + 5\r\nr8 -> rax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 160);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "155 -> r8\r\nr8 - 5\r\nr8 -> rax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 150);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "string winString \"Hello, World!\\0\"\r\n0 -> rax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		
		U8_Array *header = (U8_Array *)program.memory;
		u8 *rdata = AlignSize((u32)header[0].len, PAGE) + byte_code.memory;
		Assert(*(u64 *)rdata == 0x0e);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 0);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "string winString \"Hello, World!\\0\"\r\nwinString &-> rcx\r\n0 -> rax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		
		U8_Array *header = (U8_Array *)program.memory;
		u8 *rdata = AlignSize((u32)header[0].len, PAGE) + byte_code.memory;
		Assert(*(u64 *)rdata == 0x0e);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 0);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "string winString \"Hello, World!\\0\"\r\nrcx <-& winString\r\n0 -> rax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program);
		
		U8_Array *header = (U8_Array *)program.memory;
		u8 *rdata = AlignSize((u32)header[0].len, PAGE) + byte_code.memory;
		Assert(*(u64 *)rdata == 0x0e);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 0);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	return(0);
}