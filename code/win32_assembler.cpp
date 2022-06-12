#include <windows.h>

#include "win32_assembler.h"

global u32 PAGE;
#define OPERAND_COUNT 2

enum REX
{
    Rex_Byte = 0b01000000,
    Rex_W = 0b00001000,
    Rex_R = 0b00000100,
    Rex_X = 0b00000010,
    Rex_B = 0b00000001
};

enum MOD
{
    MOD_Pointer,
    MOD_Pointer_Displacement_U8,
    MOD_Pointer_Displacement_U32,
    MOD_Registers
};

enum Size
{
    Size_None,
    Size_8 = sizeof(u8),
    Size_16 = sizeof(u16),
    Size_32 = sizeof(u32),
    Size_64 = sizeof(u64)
};

enum Operand_Type
{
    Operand_Type_None,
    Operand_Type_Register,
    Operand_Type_Memory,
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

enum Opcode_Type
{
    Opcode_Type_Regular,
    Opcode_Type_Extended,
    Opcode_Type_Plus_Register
};

enum Reg_Effect
{
    Reg_Effect_Nothing,
    Reg_Effect_Sign_Extends,
    Reg_Effect_Zero_Extends
};

struct Opcode
{
    u8 machine_code;
    Opcode_Type type;
    u8 opcode_extension;
    Operand_Type operand_type[OPERAND_COUNT];
    Size operand_size[OPERAND_COUNT];
    b32 use_modrm;
    b32 into_reg;
    Reg_Effect reg_effect;
    u8 rex_byte;
};

Opcode
opc
(u8 machine_code, Opcode_Type opcode_type, u8 opcode_extension, Operand_Type op_type_0, Operand_Type op_type_1, Size operand_0_size, Size operand_1_size, b32 use_modrm, b32 into_reg, Reg_Effect reg_effect, u8 rex_byte)
{
    
    Opcode result = {};
    result.machine_code = machine_code;
    result.type = opcode_type;
    result.opcode_extension = opcode_extension;
    result.operand_type[0] = op_type_0;
    result.operand_type[1] = op_type_1;
    result.operand_size[0] = operand_0_size;
    result.operand_size[1] = operand_1_size;
    result.use_modrm = use_modrm;
    result.into_reg = into_reg;
    result.reg_effect = reg_effect;
    result.rex_byte = rex_byte;
    return(result);
}

struct Opcode_List
{
    String name;
    Opcode *start;
    u32 count;
};

void
add_opcode
(Buffer *buffer, Opcode_List *op_list, u8 machine_code, Opcode_Type opcode_type, u8 opcode_extension, Operand_Type op_type_0, Operand_Type op_type_1, Size operand_0_size, Size operand_1_size, b32 use_modrm, b32 into_reg, Reg_Effect reg_effect, u8 rex_byte)
{
    
    Opcode *to_add = (Opcode *)buffer_allocate(buffer, sizeof(Opcode));
    *to_add = opc(machine_code, opcode_type, opcode_extension, op_type_0, op_type_1, operand_0_size, operand_1_size, use_modrm, into_reg, reg_effect, rex_byte);
    op_list->count++;
    
    if(op_list->start == 0)
    {
        op_list->start = to_add;
    }
}

// TODO: I need to add a global dynamic list of operations that each have a string and a pointer to the matching opcode list, so I can search for the string and get pointed to the right list of opcodes.

struct Opcode_Name
{
    String name;
    Opcode_List *opcodes;
};

struct Opcode_Name_Table
{
    Opcode_Name *start;
    u32 count;
};

global Opcode_Name_Table name_table;

void
add_opcode_list
(Buffer *buffer, Opcode_List *list, String name)
{
    Opcode_Name *opcode_name = (Opcode_Name *)buffer_allocate(buffer, sizeof(Opcode_Name));
    
    opcode_name->name = name;
    opcode_name->opcodes = list;
    
    name_table.count++;
}

struct Instruction
{
    Opcode_List *opcode;
    Operand operands[OPERAND_COUNT];
    MOD mode;
};

Instruction
inst
(Opcode_List *opcode, Operand opr0, Operand opr1, MOD mode)
{
    
    Instruction result = {};
    result.opcode = opcode;
    result.operands[0] = opr0;
    result.operands[1] = opr1;
    result.mode = mode;
    return(result);
}

void
assemble
(Buffer *buffer, Instruction instruction)
{
    
    Opcode *operation = 0;
    for(u32 index = 0; index < instruction.opcode->count; index++)
    {
        operation = &instruction.opcode->start[index];
        
        for(u32 i = 0; i < OPERAND_COUNT; i++)
        {
            if((operation->operand_type[i] == instruction.operands[i].type) && (operation->operand_size[i] == instruction.operands[i].size))
            {
                continue;
            }
            else
            {
                operation = 0;
                break;
            }
        }
        
        if(operation != 0)
        {
            break;
        }
    }
    
    // TODO: How much of a mess is the rest of this now???
    u8 modrm = 0;
    u8 rex_byte = 0;
    u8 reg0 = (u8)(instruction.operands[0].reg & 0b00000111);
    if(operation->use_modrm)
    {
        
        u8 reg_mem = (reg0);
        if(instruction.operands[0].reg & 0b1000)
        {
            rex_byte = Rex_Byte | Rex_B;
        }
        
        u8 reg_opcode = 0;
        if(instruction.operands[1].type == Operand_Type_Register)
        {        
            reg_opcode = (u8)(instruction.operands[1].reg & 0b0111);
            if(instruction.operands[1].reg & 0b1000)
            {
                rex_byte |= Rex_Byte | Rex_R;
            }
        }
        else if(operation->type == Opcode_Type_Extended)
        {
            reg_opcode = operation->opcode_extension;
        }
        
        modrm = (u8)((instruction.mode << 6) | (reg_opcode << 3) | reg_mem);
        
    }
    
    if((instruction.operands[0].size == Size_64) || (instruction.operands[1].size == Size_64))
    {
        rex_byte |= Rex_Byte | Rex_W;
    }
    
    if(rex_byte != 0)
    {
        buffer_append_u8(buffer, rex_byte);
    }
    
    u8 op_code = operation->machine_code;
    if(operation->type == Opcode_Type_Plus_Register)
    {
        op_code = (u8)(op_code | reg0);
    }
    buffer_append_u8(buffer, op_code);
    
    if(operation->use_modrm != 0)
    {
        buffer_append_u8(buffer, modrm);
    }
    
    if(instruction.operands[1].type == Operand_Type_Immediate)
    {
        switch(instruction.operands[1].size)
        {
            case Size_8:
            {
                buffer_append_u8(buffer, (u8)instruction.operands[1].imm);
            }break;
            
            case Size_16:
            {
                buffer_append_u16(buffer, (u16)instruction.operands[1].imm);
            }break;
            
            case Size_32:
            {
                buffer_append_u32(buffer, (u32)instruction.operands[1].imm);
            }break;
            
            case Size_64:
            {
                buffer_append_u64(buffer, (u64)instruction.operands[1].imm);
            }break;
            
            case Size_None:
            {
                Assert(!"Improperly initialized immediate operand. Needs a size.");
            }break;
        };
        
    }
}

void
parse_instruction
(Buffer *buffer)
{
    
    Instruction result = {};
    
    String line = create_string(buffer, "mov rax, rcx");
    u32 ch = scan_string(line, ' ');
    Assert(ch != 0);
    
    String operation = {};
    operation.chars = line.chars;
    operation.len = ch - 1;
}

int __stdcall
WinMainCRTStartup
(void)
{
    
    //HMODULE kernel32_lib = LoadLibraryA("Kernel32.dll");
    //Exit = (fn_u32_to_void)GetProcAddress(kernel32_lib, "ExitProcess");
    
    SYSTEM_INFO SysInfo = {};
    GetSystemInfo(&SysInfo);
    Assert(SysInfo.dwPageSize != 0);
    PAGE = SysInfo.dwPageSize;
    
    Buffer buffer_functions = create_buffer(PAGE, PAGE_EXECUTE_READWRITE);
    Buffer buffer_junk = create_buffer(PAGE, PAGE_READWRITE);
    Buffer buffer_strings = create_buffer(PAGE, PAGE_READWRITE);
    
    rax = oper(Operand_Type_Register, 0, 0, Size_64);
    rcx = oper(Operand_Type_Register, 1, 0, Size_64);
    rdx = oper(Operand_Type_Register, 2, 0, Size_64);
    rbx = oper(Operand_Type_Register, 3, 0, Size_64);
    rsp = oper(Operand_Type_Register, 4, 0, Size_64);
    rbp = oper(Operand_Type_Register, 5, 0, Size_64);
    rsi = oper(Operand_Type_Register, 6, 0, Size_64);
    rdi = oper(Operand_Type_Register, 7, 0, Size_64);
    r8 = oper(Operand_Type_Register, 8, 0, Size_64);
    r9 = oper(Operand_Type_Register, 9, 0, Size_64);
    r10 = oper(Operand_Type_Register, 10, 0, Size_64);
    r11 = oper(Operand_Type_Register, 11, 0, Size_64);
    r12 = oper(Operand_Type_Register, 12, 0, Size_64);
    r13 = oper(Operand_Type_Register, 13, 0, Size_64);
    r14 = oper(Operand_Type_Register, 14, 0, Size_64);
    r15 = oper(Operand_Type_Register, 15, 0, Size_64);
    
    eax = oper(Operand_Type_Register, 0, 0, Size_32);
    ecx = oper(Operand_Type_Register, 1, 0, Size_32);
    edx = oper(Operand_Type_Register, 2, 0, Size_32);
    ebx = oper(Operand_Type_Register, 3, 0, Size_32);
    esp = oper(Operand_Type_Register, 4, 0, Size_32);
    ebp = oper(Operand_Type_Register, 5, 0, Size_32);
    esi = oper(Operand_Type_Register, 6, 0, Size_32);
    edi = oper(Operand_Type_Register, 7, 0, Size_32);
    r8d = oper(Operand_Type_Register, 8, 0, Size_32);
    r9d = oper(Operand_Type_Register, 9, 0, Size_32);
    r10d = oper(Operand_Type_Register, 10, 0, Size_32);
    r11d = oper(Operand_Type_Register, 11, 0, Size_32);
    r12d = oper(Operand_Type_Register, 12, 0, Size_32);
    r13d = oper(Operand_Type_Register, 13, 0, Size_32);
    r14d = oper(Operand_Type_Register, 14, 0, Size_32);
    r15d = oper(Operand_Type_Register, 15, 0, Size_32);
    
    Buffer buffer_opcode_table = create_buffer(PAGE, PAGE_READWRITE);
    Buffer buffer_opcode_name_table = create_buffer(PAGE, PAGE_READWRITE);
    name_table.start = (Opcode_Name *)buffer_opcode_name_table.memory;
    
    Opcode_List mov = {};
    String name = create_string(&buffer_strings, "mov");
    add_opcode_list(&buffer_opcode_name_table, &mov, name);
    
    add_opcode(&buffer_opcode_table, &mov, 0x88, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_8, Size_8, true, false, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x88, Opcode_Type_Regular, 0, Operand_Type_Memory, Operand_Type_Register, Size_8, Size_8, true, false, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x89, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_32, Size_32, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x89, Opcode_Type_Regular, 0, Operand_Type_Memory, Operand_Type_Register, Size_32, Size_32, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x89, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_64, Size_64, true, false, Reg_Effect_Zero_Extends, 0x48);
    add_opcode(&buffer_opcode_table, &mov, 0x89, Opcode_Type_Regular, 0, Operand_Type_Memory, Operand_Type_Register, Size_64, Size_64, true, false, Reg_Effect_Zero_Extends, 0x48);
    add_opcode(&buffer_opcode_table, &mov, 0x8a, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_8, Size_8, true, true, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x8a, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Memory, Size_8, Size_8, true, true, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x8b, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_32, Size_32, true, true, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x8b, Opcode_Type_Regular, 0, Operand_Type_Memory, Operand_Type_Register, Size_32, Size_32, true, true, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x8b, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_64, Size_64, true, true, Reg_Effect_Zero_Extends, 0x48);
    add_opcode(&buffer_opcode_table, &mov, 0x8b, Opcode_Type_Regular, 0, Operand_Type_Memory, Operand_Type_Register, Size_64, Size_64, true, true, Reg_Effect_Zero_Extends, 0x48);
    add_opcode(&buffer_opcode_table, &mov, 0xb0, Opcode_Type_Plus_Register, 0, Operand_Type_Register, Operand_Type_Immediate, Size_8, Size_8, true, false, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0xb8, Opcode_Type_Plus_Register, 0, Operand_Type_Register, Operand_Type_Immediate, Size_32, Size_32, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0xb8, Opcode_Type_Plus_Register, 0, Operand_Type_Register, Operand_Type_Immediate, Size_64, Size_64, true, false, Reg_Effect_Zero_Extends, 0x48);
    add_opcode(&buffer_opcode_table, &mov, 0xc6, Opcode_Type_Extended, 0, Operand_Type_Memory, Operand_Type_Immediate, Size_8, Size_8, true, false, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0xc7, Opcode_Type_Extended, 0, Operand_Type_Memory, Operand_Type_Immediate, Size_32, Size_32, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0xc7, Opcode_Type_Extended, 0, Operand_Type_Register, Operand_Type_Immediate, Size_64, Size_32, true, false, Reg_Effect_Sign_Extends, 0x48);
    add_opcode(&buffer_opcode_table, &mov, 0xc7, Opcode_Type_Extended, 0, Operand_Type_Memory, Operand_Type_Immediate, Size_64, Size_32, true, false, Reg_Effect_Sign_Extends, 0x48);
    
    Opcode_List add = {};
    name = create_string(&buffer_strings, "add");
    add_opcode_list(&buffer_opcode_name_table, &add, name);
    
    add_opcode(&buffer_opcode_table, &add, 0x83, Opcode_Type_Extended, 0, Operand_Type_Register, Operand_Type_Immediate, Size_32, Size_8, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &add, 0x83, Opcode_Type_Extended, 0, Operand_Type_Memory, Operand_Type_Immediate, Size_64, Size_8, true, false, Reg_Effect_Zero_Extends, 0x48);
    
    Opcode_List sub = {};
    name = create_string(&buffer_strings, "sub");
    add_opcode_list(&buffer_opcode_name_table, &sub, name);
    
    add_opcode(&buffer_opcode_table, &add, 0x83, Opcode_Type_Extended, 5, Operand_Type_Register, Operand_Type_Immediate, Size_32, Size_8, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &add, 0x83, Opcode_Type_Extended, 5, Operand_Type_Memory, Operand_Type_Immediate, Size_64, Size_8, true, false, Reg_Effect_Zero_Extends, 0x48);
    
    Opcode_List ret = {};
    name = create_string(&buffer_strings, "ret");
    add_opcode_list(&buffer_opcode_name_table, &ret, name);
    
    add_opcode(&buffer_opcode_table, &ret, 0xc3, Opcode_Type_Regular, 0, Operand_Type_None, Operand_Type_None, Size_None, Size_None, false, false, Reg_Effect_Nothing, 0);
    
    // TESTS
    
#if 0    
    {
        fn_void_to_void test = (fn_void_to_void)buffer_functions.end;
        
        buffer_append_u8(&buffer_functions, 0x48);
        buffer_append_u8(&buffer_functions, 0xb9);
        buffer_append_u8(&buffer_functions, 0x00);
        buffer_append_u8(&buffer_functions, 0x00);
        buffer_append_u8(&buffer_functions, 0x00);
        buffer_append_u8(&buffer_functions, 0x00);
        buffer_append_u8(&buffer_functions, 0x00);
        buffer_append_u8(&buffer_functions, 0x00);
        buffer_append_u8(&buffer_functions, 0x00);
        buffer_append_u8(&buffer_functions, 0x2a);
        buffer_append_u8(&buffer_functions, 0x83);
        buffer_append_u8(&buffer_functions, 0xc1);
        buffer_append_u8(&buffer_functions, 0xff);
        buffer_append_u8(&buffer_functions, 0xc3);
        
        test();
    }
#endif
    
    {
        fn_s64_to_s64 some_number = (fn_s64_to_s64)buffer_functions.end;
        
        assemble(&buffer_functions, inst(&mov, rax, rcx, MOD_Registers));
        assemble(&buffer_functions, inst(&ret, no_operand, no_operand, MOD_Registers));
        
        s64 result = some_number(42);
        Assert(result == 42);
    }
    
    {
        fn_void_to_s32 the_answer = (fn_void_to_s32)buffer_functions.end;
        
        Operand imm64 = oper(Operand_Type_Immediate, 0, 42, Size_64);
        
        assemble(&buffer_functions, inst(&mov, rax, imm64, MOD_Registers));
        assemble(&buffer_functions, inst(&mov, rcx, imm64, MOD_Registers));
        assemble(&buffer_functions, inst(&ret, no_operand, no_operand, MOD_Registers));
        
        s64 result = the_answer();
        Assert(result == 42);
    }
    
    {
        fn_s64_to_void write_to_pointer  = (fn_s64_to_void)buffer_functions.end;
        
        Operand imm64 = oper(Operand_Type_Immediate, 0, 42, Size_64);
        
        assemble(&buffer_functions, inst(&mov, rax, imm64, MOD_Registers));
        assemble(&buffer_functions, inst(&mov, rcx, rax, MOD_Pointer));
        assemble(&buffer_functions, inst(&ret, no_operand, no_operand, MOD_Registers));
        
        write_to_pointer((s64)buffer_junk.memory);
        Assert(*(s64 *)buffer_junk.memory == 42);
    }
    
    {
        fn_s64_to_s64 not_the_answer = (fn_s64_to_s64)buffer_functions.end;
        
        Operand imm8 = oper(Operand_Type_Immediate, 0, 1, Size_8);
        
        assemble(&buffer_functions, inst(&sub, rcx, imm8, MOD_Registers));
        assemble(&buffer_functions, inst(&mov, rax, rcx, MOD_Registers));
        assemble(&buffer_functions, inst(&ret, no_operand, no_operand, MOD_Registers));
        
        s64 result = not_the_answer(42);
        Assert(result == 41);
    }
    
    parse_instruction(&buffer_strings);
    
    ExitProcess(0);
}