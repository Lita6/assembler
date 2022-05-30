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

enum Operand_Type
{
    Operand_Type_None,
    Operand_Type_Register,
    Operand_Type_Immediate
};

struct Operand
{
    
    Operand_Type type;
    u8 reg;
    u64 imm;
    Size size;
};

global Operand no_oprnd;
global Operand rax;
global Operand rcx;
global Operand rdx;
global Operand rbx;
global Operand rsp;
global Operand rbp;
global Operand rsi;
global Operand rdi;
global Operand r8;
global Operand r9;
global Operand r10;
global Operand r11;
global Operand r12;
global Operand r13;
global Operand r14;
global Operand r15;

Operand
oper
(Operand_Type type, u8 reg, u64 imm, Size size)
{
    
    Operand result = {};
    result.type = type;
    result.reg = reg;
    result.imm = imm;
    result.size = size;
    return(result);
}

struct OpCode
{
    u8 op_code;
    Operand_Type operand_type[2];
    b32 use_modrm;
};

OpCode
opc
(u8 op_code, Operand_Type op_type_0, Operand_Type op_type_1, b32 use_modrm)
{
    
    OpCode result = {};
    result.op_code = op_code;
    result.operand_type[0] = op_type_0;
    result.operand_type[1] = op_type_1;
    result.use_modrm = use_modrm;
    return(result);
}

struct OpCode_List
{
    OpCode *start;
    u32 count;
};

void
assemble
(Buffer *buffer, OpCode opcode, Operand opr0, Operand opr1)
{
    
    // TODO: Collapse this code with an Instruction struct
    if(opcode.operand_type[0] != opr0.type)
    {
        Assert(!"Opcode doesn't match operands.");
    }
    
    if(opcode.operand_type[1] != opr1.type)
    {
        Assert(!"Opcode doesn't match operands.");
    }
    
    u8 modrm = 0;
    u8 rex_byte = 0;
    if(opcode.use_modrm)
    {
        
        u8 reg_mem = (opr0.reg & 0b0111);
        if(opr0.reg & 0b1000)
        {
            rex_byte = Rex_Byte | Rex_B;
        }
        
        u8 reg_opcode = 0;
        if(opr1.type == Operand_Type_Register)
        {        
            reg_opcode = (opr1.reg & 0b0111);
            if(opr1.reg & 0b1000)
            {
                rex_byte |= Rex_Byte | Rex_R;
            }
        }
        
        // Doing registers only for now.
        modrm = 0b11000000 | (reg_opcode << 3) | reg_mem;
        
    }
    
    if((opr0.size == Size_U64) || (opr1.size == Size_U64))
    {
        rex_byte |= Rex_Byte | Rex_W;
    }
    
    if(rex_byte != 0)
    {
        buffer_append_u8(buffer, rex_byte);
    }
    
    buffer_append_u8(buffer, opcode.op_code);
    
    if(modrm != 0)
    {
        buffer_append_u8(buffer, modrm);
    }
    
    if(opr1.type == Operand_Type_Immediate)
    {
        switch(opr1.size)
        {
            case Size_U8:
            {
                buffer_append_u8(buffer, (u8)opr1.imm);
            }break;
            
            case Size_U16:
            {
                buffer_append_u16(buffer, (u16)opr1.imm);
            }break;
            
            case Size_U32:
            {
                buffer_append_u32(buffer, (u32)opr1.imm);
            }break;
            
            case Size_U64:
            {
                buffer_append_u64(buffer, (u64)opr1.imm);
            }break;
        };
        
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
    
    rax = oper(Operand_Type_Register, 0, 0, Size_U64);
    rcx = oper(Operand_Type_Register, 1, 0, Size_U64);
    rdx = oper(Operand_Type_Register, 2, 0, Size_U64);
    rbx = oper(Operand_Type_Register, 3, 0, Size_U64);
    rsp = oper(Operand_Type_Register, 4, 0, Size_U64);
    rbp = oper(Operand_Type_Register, 5, 0, Size_U64);
    rsi = oper(Operand_Type_Register, 6, 0, Size_U64);
    rdi = oper(Operand_Type_Register, 7, 0, Size_U64);
    r8 = oper(Operand_Type_Register, 8, 0, Size_U64);
    r9 = oper(Operand_Type_Register, 9, 0, Size_U64);
    r10 = oper(Operand_Type_Register, 10, 0, Size_U64);
    r11 = oper(Operand_Type_Register, 11, 0, Size_U64);
    r12 = oper(Operand_Type_Register, 12, 0, Size_U64);
    r13 = oper(Operand_Type_Register, 13, 0, Size_U64);
    r14 = oper(Operand_Type_Register, 14, 0, Size_U64);
    r15 = oper(Operand_Type_Register, 15, 0, Size_U64);
    
    // TODO: Make 32 bit versions of the registers.
    
    Buffer buffer_opcode_table = create_buffer(PAGE, PAGE_READWRITE);
    
    // TODO: Implement the opcode lookup.
    //Opcode_List mov = {};
    //mov.start = (OpCode *)buffer_allocate(&buffer_opcode_table, sizeof(OpCode));
    //OpCode *opcode = mov.start;
    //*opcode = opc(0x89, 2, true);
    //mov.count++;
    //opcode = (OpCode *)buffer_allocate(&buffer_opcode_table, sizeof(OpCode));
    //*opcode = opc(, , );
    //mov.count++;
    
    OpCode mov0 = opc(0x89, Operand_Type_Register, Operand_Type_Register, true);
    OpCode mov1 = opc(0xc7, Operand_Type_Register, Operand_Type_Immediate, true);
    
    OpCode ret = opc(0xc3, Operand_Type_None, Operand_Type_None, false);
    
    {    
        
        fn_s64_to_s64 some_number = (fn_s64_to_s64)buffer_functions.end;
        
        assemble(&buffer_functions, mov0, rdx, rcx);
        assemble(&buffer_functions, mov0, r8, rdx);
        assemble(&buffer_functions, mov0, r9, r8);
        assemble(&buffer_functions, mov0, rax, r9);
        assemble(&buffer_functions, ret, no_oprnd, no_oprnd);
        
        s64 result = some_number(42);
        Assert(result == 42);
    }
    
    {
        
        fn_void_to_s32 the_answer = (fn_void_to_s32)buffer_functions.end;
        
        // mov rax, 42
        
        // TODO: When the opcode itself contains the register index, it needs to be properly
        //       handled in the assemble function.
        //buffer_append_u8(&buffer_functions, 0x48);
        //buffer_append_u8(&buffer_functions, 0xb8);
        //buffer_append_u64(&buffer_functions, 42);
        //buffer_append_u8(&buffer_functions, 0xc3);
        
        Operand imm32 = oper(Operand_Type_Immediate, 0, 42, Size_U32);
        
        assemble(&buffer_functions, mov1, rax, imm32);
        assemble(&buffer_functions, ret, no_oprnd, no_oprnd);
        
        s32 result = the_answer();
        Assert(result == 42);
    }
    
    return(0);
}