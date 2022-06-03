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

global Operand no_operand;

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

global Operand eax;
global Operand ecx;
global Operand edx;
global Operand ebx;
global Operand esp;
global Operand ebp;
global Operand esi;
global Operand edi;
global Operand r8d;
global Operand r9d;
global Operand r10d;
global Operand r11d;
global Operand r12d;
global Operand r13d;
global Operand r14d;
global Operand r15d;

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

enum OpCode_Type
{
    OpCode_Type_Regular,
    OpCode_Type_Extended,
    OpCode_Type_Plus_Register
};

struct OpCode
{
    u8 opcode;
    OpCode_Type type;
    u8 opcode_extension;
    Operand_Type operand_type[2];
    Size max_imm_size;
    b32 use_modrm;
};

OpCode
opc
(u8 opcode, OpCode_Type opcode_type, u8 opcode_extension, Operand_Type op_type_0, Operand_Type op_type_1, Size max_imm_size, b32 use_modrm)
{
    
    OpCode result = {};
    result.opcode = opcode;
    result.type = opcode_type;
    result.opcode_extension = opcode_extension;
    result.operand_type[0] = op_type_0;
    result.operand_type[1] = op_type_1;
    result.max_imm_size = max_imm_size;
    result.use_modrm = use_modrm;
    return(result);
}

struct OpCode_List
{
    OpCode *start;
    u32 count;
};

global OpCode_List mov;
global OpCode_List ret;

void
add_opcode
(Buffer *buffer, OpCode_List *op_list, u8 opcode, OpCode_Type opcode_type, u8 opcode_extension, Operand_Type op_type_0, Operand_Type op_type_1, Size max_imm_size, b32 use_modrm)
{
    
    OpCode *to_add = (OpCode *)buffer_allocate(buffer, sizeof(OpCode));
    *to_add = opc(opcode, opcode_type, opcode_extension, op_type_0, op_type_1, max_imm_size, use_modrm);
    op_list->count++;
    
    if(op_list->start == 0)
    {
        op_list->start = to_add;
    }
}

struct Instruction
{
    OpCode_List *opcode;
    Operand operands[2];
};

Instruction
inst
(OpCode_List *opcode, Operand opr0, Operand opr1)
{
    
    Instruction result = {};
    result.opcode = opcode;
    result.operands[0] = opr0;
    result.operands[1] = opr1;
    return(result);
}

void
assemble
(Buffer *buffer, Instruction instruction)
{
    
    OpCode *opcode = 0;
    for(u32 i = 0; i < instruction.opcode->count; i++)
    {
        opcode = instruction.opcode->start + i;
        u32 match = 0;
        for(u32 i = 0; i < 2; i++)
        {
            if(opcode->operand_type[i] == instruction.operands[i].type)
            {
                
                match++;
                
                if((instruction.operands[i].size > opcode->max_imm_size) && (opcode->operand_type[i] == Operand_Type_Immediate))
                {
                    match--;
                }
            }
        }
        
        if(match == 2)
        {
            break;
        }
        else
        {
            opcode = 0;
        }
    }
    
    if(opcode == 0)
    {
        Assert(!"Didn't find an opcode");
    }
    
    u8 modrm = 0;
    u8 rex_byte = 0;
    u8 reg0 = instruction.operands[0].reg & 0b0111;
    if(opcode->use_modrm)
    {
        
        u8 reg_mem = (reg0);
        if(instruction.operands[0].reg & 0b1000)
        {
            rex_byte = Rex_Byte | Rex_B;
        }
        
        u8 reg_opcode = 0;
        if(instruction.operands[1].type == Operand_Type_Register)
        {        
            reg_opcode = (instruction.operands[1].reg & 0b0111);
            if(instruction.operands[1].reg & 0b1000)
            {
                rex_byte |= Rex_Byte | Rex_R;
            }
        }
        else if(opcode->type == OpCode_Type_Extended)
        {
            reg_opcode = opcode->opcode_extension;
        }
        
        // TODO: Properly set mode.
        modrm = 0b11000000 | (reg_opcode << 3) | reg_mem;
        
    }
    
    if((instruction.operands[0].size == Size_U64) || (instruction.operands[1].size == Size_U64))
    {
        rex_byte |= Rex_Byte | Rex_W;
    }
    
    if(rex_byte != 0)
    {
        buffer_append_u8(buffer, rex_byte);
    }
    
    u8 op_code = opcode->opcode;
    if(opcode->type == OpCode_Type_Plus_Register)
    {
        op_code = op_code | reg0;
    }
    buffer_append_u8(buffer, op_code);
    
    if(modrm != 0)
    {
        buffer_append_u8(buffer, modrm);
    }
    
    if(instruction.operands[1].type == Operand_Type_Immediate)
    {
        switch(instruction.operands[1].size)
        {
            case Size_U8:
            {
                buffer_append_u8(buffer, (u8)instruction.operands[1].imm);
            }break;
            
            case Size_U16:
            {
                buffer_append_u16(buffer, (u16)instruction.operands[1].imm);
            }break;
            
            case Size_U32:
            {
                buffer_append_u32(buffer, (u32)instruction.operands[1].imm);
            }break;
            
            case Size_U64:
            {
                buffer_append_u64(buffer, (u64)instruction.operands[1].imm);
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
    
    eax = oper(Operand_Type_Register, 0, 0, Size_U32);
    ecx = oper(Operand_Type_Register, 1, 0, Size_U32);
    edx = oper(Operand_Type_Register, 2, 0, Size_U32);
    ebx = oper(Operand_Type_Register, 3, 0, Size_U32);
    esp = oper(Operand_Type_Register, 4, 0, Size_U32);
    ebp = oper(Operand_Type_Register, 5, 0, Size_U32);
    esi = oper(Operand_Type_Register, 6, 0, Size_U32);
    edi = oper(Operand_Type_Register, 7, 0, Size_U32);
    r8d = oper(Operand_Type_Register, 8, 0, Size_U32);
    r9d = oper(Operand_Type_Register, 9, 0, Size_U32);
    r10d = oper(Operand_Type_Register, 10, 0, Size_U32);
    r11d = oper(Operand_Type_Register, 11, 0, Size_U32);
    r12d = oper(Operand_Type_Register, 12, 0, Size_U32);
    r13d = oper(Operand_Type_Register, 13, 0, Size_U32);
    r14d = oper(Operand_Type_Register, 14, 0, Size_U32);
    r15d = oper(Operand_Type_Register, 15, 0, Size_U32);
    
    Buffer buffer_opcode_table = create_buffer(PAGE, PAGE_READWRITE);
    
    add_opcode(&buffer_opcode_table, &mov, 0x89, OpCode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_None, true);
    add_opcode(&buffer_opcode_table, &mov, 0xc7, OpCode_Type_Extended, 0, Operand_Type_Register, Operand_Type_Immediate, Size_U32, true);
    add_opcode(&buffer_opcode_table, &mov, 0xb8, OpCode_Type_Plus_Register, 0, Operand_Type_Register, Operand_Type_Immediate, Size_U64, false);
    
    add_opcode(&buffer_opcode_table, &ret, 0xc3, OpCode_Type_Regular, 0, Operand_Type_None, Operand_Type_None, Size_None, false);
    
    {    
        
        fn_s64_to_s64 some_number = (fn_s64_to_s64)buffer_functions.end;
        
        assemble(&buffer_functions, inst(&mov, edx, ecx));
        assemble(&buffer_functions, inst(&mov, r8d, edx));
        assemble(&buffer_functions, inst(&mov, r9d, r8d));
        assemble(&buffer_functions, inst(&mov, eax, r9d));
        assemble(&buffer_functions, inst(&ret, no_operand, no_operand));
        
        s64 result = some_number(42);
        Assert(result == 42);
    }
    
    {
        
        fn_void_to_s32 the_answer = (fn_void_to_s32)buffer_functions.end;
        
        Operand imm64 = oper(Operand_Type_Immediate, 0, 42, Size_U64);
        
        assemble(&buffer_functions, inst(&mov, rax, imm64));
        assemble(&buffer_functions, inst(&mov, rcx, imm64));
        assemble(&buffer_functions, inst(&ret, no_operand, no_operand));
        
        s64 result = the_answer();
        Assert(result == 42);
    }
    
    return(0);
}