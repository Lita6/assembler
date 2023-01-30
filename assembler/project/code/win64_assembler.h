/* date = December 25th 2022 5:29 pm */

#ifndef WIN64_ASSEMBLER_H
#define WIN64_ASSEMBLER_H

/*
*
* NOTE: TYPES
*
*/

#include <stdint.h>
#include <stddef.h>

#define global static

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define MAX_U8 0xFF
#define MAX_U16 0XFFFF
#define MAX_U32 0xFFFFFFFF
#define MAX_U64 0XFFFFFFFFFFFFFFFF

global u8 size_8 = sizeof(u8);
global u8 size_16 = sizeof(u16);
global u8 size_32 = sizeof(u32);
global u8 size_64 = sizeof(u64);

typedef s8 b8;
typedef s16 b16;
typedef s32 b32;

#define TRUE 1
#define FALSE 0

// NOTE: This is needed for the linker to use floats
int _fltused;

typedef float r32;
typedef double r64;

#define Assert(Expression) if(!(Expression)) {*(int *)0 = 0;}
#define unreferenced(name) (void)(name)

u32
SafeTruncateS64toU32(s64 Value)
{
	Assert(Value >= 0);
	Assert(Value <= MAX_U32);
	u32 Result = (u32)Value;
	return(Result);
}

struct read_file_result
{
	u32 ContentsSize;
	void *Contents;
};

void 
Win64FreeMemory
(void *Memory)
{
	if(Memory)
	{
		VirtualFree(Memory, 0, MEM_RELEASE);
	}
}

read_file_result
Win64ReadEntireFile
(char *FileName)
{
	read_file_result Result = {};
	
	HANDLE FileHandle = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if(FileHandle != INVALID_HANDLE_VALUE)
	{
		LARGE_INTEGER FileSize;
		if(GetFileSizeEx(FileHandle, &FileSize))
		{
			u32 FileSize32 = SafeTruncateS64toU32((s64)FileSize.QuadPart);
			Result.Contents = VirtualAlloc(0, FileSize32, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			if(Result.Contents)
			{
				DWORD BytesRead;
				if(ReadFile(FileHandle, Result.Contents, FileSize32, &BytesRead, 0) && (FileSize32 == BytesRead))
				{
					Result.ContentsSize = FileSize32;
				}
				else
				{
					Win64FreeMemory(Result.Contents);
					Result.Contents = 0;
				}
			}
			else
			{
				Assert(!"Failed to allocate memory for file read.\n");
			}
		}
		else
		{
			Assert(!"Failed to get file size after opening.\n");
		}
		
		CloseHandle(FileHandle);
	}
	else
	{
		Assert(!"Failed to open file.\n");
	}
	
	return(Result);
}

b32
Win64WriteEntireFile(char *FileName, u32 MemorySize, void *Memory)
{
	b32 Result = FALSE;
	
	HANDLE FileHandle = CreateFileA(FileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	if(FileHandle != INVALID_HANDLE_VALUE)
	{
		DWORD BytesWritten;
		if(WriteFile(FileHandle, Memory, MemorySize, &BytesWritten, 0))
		{
			Result = (BytesWritten == MemorySize);
		}
		else
		{
			Assert(!"Failed to write file.\n");
		}
		
		CloseHandle(FileHandle);
	}
	else
	{
		Assert(!"Failed to create file to write.\n");
	}
	
	return(Result);
}

struct Buffer
{
	u8 *memory;
	u8 *end;
	u32 size;
};

void
clear_buffer
(Buffer *buffer)
{
	for(u8 *i = buffer->memory; i < buffer->end; i++)
	{
		*i = 0;
	}
	buffer->end = buffer->memory;
}

u8 *
buffer_allocate
(Buffer *buffer, u32 amount)
{
	
	Assert((buffer->end + amount) <= (buffer->memory + buffer->size));
	
	u8 *Result = buffer->end;
	buffer->end += amount;
	
	return(Result);
}

#define define_buffer_append(Type) \
inline void \
buffer_append_##Type \
(Buffer *buffer, Type value) \
{ \
Assert((buffer->end + sizeof(Type)) <= (buffer->memory + buffer->size)); \
*(Type *)buffer->end = value; \
buffer->end += sizeof(Type); \
}

define_buffer_append(s8)
define_buffer_append(s16)
define_buffer_append(s32)
define_buffer_append(s64)

define_buffer_append(u8)
define_buffer_append(u16)
define_buffer_append(u32)
define_buffer_append(u64)
#undef define_buffer_append

Buffer
win64_make_buffer
(u32 size, u32 permission)
{
	Buffer buffer = {};
	buffer.memory = (u8 *)(VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, permission));
	Assert(buffer.memory);
	buffer.end = buffer.memory;
	buffer.size = size;
	
	return(buffer);
}

Buffer
create_buffer
(Buffer *mem, u32 size)
{
	
	Buffer result = {};
	result.memory = buffer_allocate(mem, size);
	result.end = result.memory;
	result.size = size;
	
	return(result);
}

struct String
{
	u8 *chars;
	u64 len;
};

b32
operator==
(String a, String b)
{
	b32 result = TRUE;
	
	if(a.len != b.len)
	{
		result = FALSE;
		
	}
	else
	{
		for(u64 i = 0; i < a.len; i++)
		{
			
			if(a.chars[i] != b.chars[i])
			{
				result = FALSE;
				break;
				
			}
		}
	}
	
	return(result);
}

String
create_string
(Buffer *buffer, char *str)
{
	
	String result = {};
	result.chars = buffer->end;
	
	u8 *index = (u8 *)str;
	while(*index)
	{
		buffer_append_u8(buffer, *index++);
		result.len++;
	}
	
	return(result);
}

u32
GetStringLength
(u8 *chars)
{
	u32 result = 0;
	
	while(*chars++ != 0)
	{
		result++;
	}
	
	return(result);
}

b32
IsNumber
(String string)
{
	
	b32 result = TRUE;
	for(u64 i = 0; i < string.len; i++)
	{
		
		if((string.chars[i] < '0') || (string.chars[i] > '9'))
		{
			result = FALSE;
		}
	}
	
	return(result);
}

b32
IsWhiteSpace
(u8 ch)
{
	
	b32 result = FALSE;
	if((ch == ' ') || (ch == '\t') || (ch == '\r') || (ch == '\n'))
	{
		result = TRUE;
	}
	return(result);
}

u8
ConvertNumToHex
(char letter, String Hexadecimals)
{
	if((letter >= 'a') && (letter <= 'f'))
	{
		letter += 'A' - 'a';
	}
	
	for(u8 i = 0; i < Hexadecimals.len; i++)
	{
		if(letter == Hexadecimals.chars[i])
		{
			return(i);
		}
	}
	
	return(MAX_U8);
}

u64
StringToU64
(String string)
{
	u64 Result = 0;
	
	for(u64 i = 0; i < string.len; i++)
	{
		Result = Result + (string.chars[i] - '0');
		
		if(i != (string.len - 1))
		{
			Result = Result * 10;
		}
	}
	
	return(Result);
}

s64
StringToS64
(String string)
{
	s64 Result = 0;
	
	u32 neg = 0;
	if(string.chars[0] == '-')
	{
		neg = 1;
	}
	
	for(u64 i = neg; i < string.len; i++)
	{
		Result = Result + (string.chars[i] - '0');
		
		if(i != (string.len - 1))
		{
			Result = Result * 10;
		}
	}
	
	if(neg != 0)
	{
		Result = Result * -1;
	}
	
	return(Result);
}

struct U8_Array
{
	u8 *bytes;
	u64 len;
};

u32
AlignSize
(u32 size, u32 align)
{
	u32 result = 0;
	
	u32 mod = size % align;
	if(mod != 0)
	{
		result = size + (align - mod);
	}
	else
	{
		result = size;
	}
	
	return(result);
}

#endif //WIN64_ASSEMBLER_H
