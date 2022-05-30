/* date = May 28th 2022 4:58 pm */

#ifndef WIN32_ASSEMBLER_H
#define WIN32_ASSEMBLER_H

#include <stdint.h>

#define internal static
#define local static
#define global static

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef s32 b32;
typedef float r32;
typedef double r64;

#define Assert(Expression) if(!(Expression)) {*(int *)0 = 0;}

#define ArrayCount(Array) (sizeof(Array) / sizeof((Array)[0]))

struct Buffer
{
    u8 *memory;
    u8 *end;
    s32 size;
};

Buffer
create_buffer
(s32 size, u64 permission)
{
    Buffer buffer = {};
    buffer.memory = (u8 *)(VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, permission));
    Assert(buffer.memory);
    buffer.end = buffer.memory;
    buffer.size = size;
    
    return(buffer);
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

define_buffer_append(u8)
define_buffer_append(u16)
define_buffer_append(u32)
define_buffer_append(u64)
#undef define_buffer_append

typedef s64 (*fn_s64_to_s64)(s64);
typedef s64 (*fn_void_to_s64)();
typedef s32 (*fn_void_to_s32)();

#endif //WIN32_ASSEMBLER_H
