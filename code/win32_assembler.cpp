#include <windows.h>

#include "win32_assembler.h"

global u32 PAGE;

enum REX
{
    Rex_Byte = 0b01000000,
    Rex_W = 0b00001000,
    Rex_R = 0b00000100,
    Rex_X = 0b00000010,
    Rex_B = 0b00000001
};

enum Size
{
    Size_None,
    Size_U8 = sizeof(u8),
    Size_U16 = sizeof(u16),
    Size_U32 = sizeof(u32),
    Size_U64 = sizeof(u64)
};

struct Register
{
    u8 index;
    Size size;
};

global Register no_reg;
global Register rax;
global Register rcx;
global Register rdx;
global Register rbx;
global Register rsp;
global Register rbp;
global Register rsi;
global Register rdi;
global Register r8;
global Register r9;
global Register r10;
global Register r11;
global Register r12;
global Register r13;
global Register r14;
global Register r15;

Register
reg
(u8 index, Size size)
{
    
    Register result = {};
    result.index = index;
    result.size = size;
    return(result);
}

struct OpCode
{
    u8 op_code;
    u32 operand_count;
    b32 use_modrm;
};

OpCode
opc
(u8 op_code, u32 operand_count, b32 use_modrm)
{
    
    OpCode result = {};
    result.op_code = op_code;
    result.operand_count = operand_count;
    result.use_modrm = use_modrm;
    return(result);
}

void
assemble
(Buffer *buffer, OpCode opcode, Register reg0, Register reg1)
{
    
    if(reg0.size == reg1.size)
    {
        
        u32 operand_count = 0;
        if(reg0.size)
        {
            operand_count++;
        }
        if(reg1.size)
        {
            operand_count++;
        }
        Assert(operand_count == opcode.operand_count);
        
        u8 modrm = 0;
        u8 rex_byte = 0;
        if(opcode.use_modrm)
        {
            u8 reg_mem = (reg0.index & 0b0111);
            if(reg0.index & 0b1000)
            {
                rex_byte = Rex_Byte | Rex_B;
            }
            
            u8 reg_opcode = (reg1.index & 0b0111);
            if(reg1.index & 0b1000)
            {
                rex_byte |= Rex_Byte | Rex_R;
            }
            
            // Doing registers only for now.
            modrm = 0b11000000 | (reg_opcode << 3) | reg_mem;
            
        }
        
        if(reg0.size == Size_U64)
        {
            rex_byte |= Rex_Byte | Rex_W;
            buffer_append_u8(buffer, rex_byte);
        }
        
        buffer_append_u8(buffer, opcode.op_code);
        
        if(modrm)
        {
            buffer_append_u8(buffer, modrm);
        }
        
    }
    else
    {
        Assert(!"Registers not the same size.");
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
    
    Buffer buffer_functions = create_buffer(PAGE, PAGE_EXECUTE_READWRITE);
    
    rax = reg(0, Size_U64);
    rcx = reg(1, Size_U64);
    rdx = reg(2, Size_U64);
    rbx = reg(3, Size_U64);
    rsp = reg(4, Size_U64);
    rbp = reg(5, Size_U64);
    rsi = reg(6, Size_U64);
    rdi = reg(7, Size_U64);
    r8 = reg(8, Size_U64);
    r9 = reg(9, Size_U64);
    r10 = reg(10, Size_U64);
    r11 = reg(11, Size_U64);
    r12 = reg(12, Size_U64);
    r13 = reg(13, Size_U64);
    r14 = reg(14, Size_U64);
    r15 = reg(15, Size_U64);
    
    OpCode mov = opc(0x89, 2, true);
    OpCode ret = opc(0xc3, 0, false);
    
    {    
        
        assemble(&buffer_functions, mov, rdx, rcx);
        assemble(&buffer_functions, mov, r8, rdx);
        assemble(&buffer_functions, mov, r9, r8);
        assemble(&buffer_functions, mov, rax, r9);
        assemble(&buffer_functions, ret, no_reg, no_reg);
        
        fn_type_s64_to_s64 some_number = (fn_type_s64_to_s64)buffer_functions.memory;
        s64 result = some_number(42);
        Assert(result == 42);
    }
    
    return(0);
}