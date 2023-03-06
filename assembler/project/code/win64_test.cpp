#include <windows.h>

#include "assembler.cpp"

global u32 PAGE;

void
loadProgram
(Buffer *bytes, Buffer program, HMODULE kernel32)
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
		Import_Data_Table *import = (Import_Data_Table *)bytes->end;
		
		for(u64 i = 0; i < header[1].len; i++)
		{
			buffer_append_u8(bytes, header[1].bytes[i]);
		}
		
		import->load_lib_address = (u64)GetProcAddress(kernel32, "LoadLibraryA");
		import->get_proc_address = (u64)GetProcAddress(kernel32, "GetProcAddress");
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
	
	HMODULE kernel32 = LoadLibraryA("KERNEL32.dll");
	
	Buffer AssembleMemory = win64_make_buffer((2*PAGE), PAGE_READWRITE);
	
	Buffer byte_code = win64_make_buffer(2*PAGE, PAGE_EXECUTE_READWRITE);
	Buffer program = win64_make_buffer(PAGE, PAGE_READWRITE);
	Buffer file = win64_make_buffer(PAGE, PAGE_READWRITE);
	
	{
		String src = create_string(&file, "ret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
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
		loadProgram(&byte_code, program, kernel32);
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
		loadProgram(&byte_code, program, kernel32);
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
		loadProgram(&byte_code, program, kernel32);
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
		loadProgram(&byte_code, program, kernel32);
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
		loadProgram(&byte_code, program, kernel32);
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
		loadProgram(&byte_code, program, kernel32);
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
		loadProgram(&byte_code, program, kernel32);
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
		loadProgram(&byte_code, program, kernel32);
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
		loadProgram(&byte_code, program, kernel32);
		
		U8_Array *header = (U8_Array *)program.memory;
		u8 *rdata = AlignSize((u32)header[0].len, PAGE) + byte_code.memory;
		u64 *string_len = (u64 *)(rdata + sizeof(Import_Data_Table));
		Assert(*string_len == 0x0e);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 0);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "string winString \"Hello, World!\\0\"\r\nwinString &-> rcx\r\nrcx -> rax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		U8_Array *header = (U8_Array *)program.memory;
		u8 *rdata = AlignSize((u32)header[0].len, PAGE) + byte_code.memory;
		u64 *string_len = (u64 *)(rdata + sizeof(Import_Data_Table));
		Assert(*string_len == 0x0e);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == (u64)((u8 *)string_len + size_64));
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "string winString \"Hello, World!\\0\"\r\nrcx <-& winString\r\nrcx -> rax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		U8_Array *header = (U8_Array *)program.memory;
		u8 *rdata = AlignSize((u32)header[0].len, PAGE) + byte_code.memory;
		u64 *string_len = (u64 *)(rdata + sizeof(Import_Data_Table));
		Assert(*string_len == 0x0e);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == (u64)((u8 *)string_len + size_64));
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "kernel32_name &-> rax\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		U8_Array *header = (U8_Array *)program.memory;
		Import_Data_Table *import = (Import_Data_Table *)(AlignSize((u32)header[0].len, PAGE) + byte_code.memory);
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == (u64)(import->kernel32_name));
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "LoadLibraryA &-> rax\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		U8_Array *header = (U8_Array *)program.memory;
		Import_Data_Table *import = (Import_Data_Table *)(AlignSize((u32)header[0].len, PAGE) + byte_code.memory);
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == (u64)(&import->load_lib_address));
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "GetProcAddress &-> rax\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		U8_Array *header = (U8_Array *)program.memory;
		Import_Data_Table *import = (Import_Data_Table *)(AlignSize((u32)header[0].len, PAGE) + byte_code.memory);
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == (u64)(&import->get_proc_address));
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "rsp - 40\nkernel32_name &-> rcx\ncall LoadLibraryA\nrsp + 40\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == (u64)kernel32);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "STACK_ADJUST -> rax\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 0x28);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "rsp - STACK_ADJUST\nkernel32_name &-> rcx\ncall LoadLibraryA\nu64 kernel32 <- rax\nrsp + STACK_ADJUST\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		u64 stack_adjust = Reserved_Strings.start[(Reserved_Strings.count - 1)].imm_value;
		Assert(stack_adjust == (u64)(6 * size_64));
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == (u64)kernel32);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "rsp - STACK_ADJUST\n150 -> rcx\nu64 variable <- rcx\nvariable -> rax\nrsp + STACK_ADJUST\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 150);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "string winString \"Hello, World!\\n\\0\"\r\nrcx <-& winString\r\nrcx -> rax\r\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		U8_Array *header = (U8_Array *)program.memory;
		u8 *rdata = AlignSize((u32)header[0].len, PAGE) + byte_code.memory;
		u64 *string_len = (u64 *)(rdata + sizeof(Import_Data_Table));
		Assert(*string_len == 0x0f);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == (u64)((u8 *)string_len + size_64));
		Assert((s32)(*((u8 *)result + *string_len - 2)) == '\n');
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "rsp - STACK_ADJUST\n0 -> rax\nlabel function &-> rcx\ncall rcx\nrsp + STACK_ADJUST\nret\nfunction :\n155 -> rax\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 155);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	{
		String src = create_string(&file, "rsp - STACK_ADJUST\n0 -> rax\nlabel function &-> rcx\ncall rcx\nfunction &-> rdx\ncall rdx\nrsp + STACK_ADJUST\nret\nfunction :\n42 + rax\nret");
		assemble(&program, &AssembleMemory, src, PAGE);
		loadProgram(&byte_code, program, kernel32);
		
		fn_void_to_u64 test = (fn_void_to_u64)byte_code.memory;
		u64 result = test();
		Assert(result == 84);
		
		clear_buffer(&file);
		clear_buffer(&program);
		clear_buffer(&byte_code);
	}
	
	return(0);
}