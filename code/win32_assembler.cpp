#include <windows.h>

#include "win32_assembler.h"

global u32 PAGE;
#define OPERAND_COUNT 2

enum REX
{
    Rex_Empty = 0b01000000,
    Rex_W = 0b01001000,
    Rex_R = 0b01000100,
    Rex_X = 0b01000010,
    Rex_B = 0b01000001
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

struct Operand_Name
{
    String name;
    Operand *operand;
};

struct Operand_Name_List
{
    Operand_Name *start;
    u32 count;
};

void
add_operand
(Buffer *buffer, Operand_Name_List *list, String name, Operand *operand)
{
    
    Operand_Name *entry = (Operand_Name *)buffer_allocate(buffer, sizeof(Operand_Name));
    
    entry->name = name;
    entry->operand = operand;
    
    list->count++;
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
    u8 extension;
    Operand_Type operand_type[OPERAND_COUNT];
    Size operand_size[OPERAND_COUNT];
    b32 use_modrm;
    b32 into_reg;
    Reg_Effect reg_effect;
    u8 rex_byte;
};

Opcode
opc
(u8 machine_code, Opcode_Type opcode_type, u8 extension, Operand_Type op_type_0, Operand_Type op_type_1, Size operand_0_size, Size operand_1_size, b32 use_modrm, b32 into_reg, Reg_Effect reg_effect, u8 rex_byte)
{
    
    Opcode result = {};
    result.machine_code = machine_code;
    result.type = opcode_type;
    result.extension = extension;
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

struct Opcode_Name
{
    String name;
    Opcode_List *opcode;
};

struct Opcode_Name_Table
{
    Opcode_Name *start;
    u32 count;
};

void
add_opcode_list
(Buffer *buffer, Opcode_Name_Table *name_table, String name, Opcode_List *list)
{
    Opcode_Name *opcode_name = (Opcode_Name *)buffer_allocate(buffer, sizeof(Opcode_Name));
    
    opcode_name->name = name;
    opcode_name->opcode = list;
    
    name_table->count++;
}

struct Instruction
{
    Opcode_List *opcode;
    Operand operands[OPERAND_COUNT];
};

Instruction
inst
(Opcode_List *opcode, Operand opr0, Operand opr1)
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
    
    Assert(operation != 0);
    
    u8 reg_opcode = 0;
    u8 reg_mem = 0;
    u8 opcode = operation->machine_code;
    u8 rex_byte = operation->rex_byte;
    if(operation->type == Opcode_Type_Regular)
    {
        
        if(operation->use_modrm == 1)
        {
            u8 mem_index = 0;
            u8 reg_index = 0;
            if(operation->into_reg == 0)
            {
                reg_index = 1;
            }
            else
            {
                mem_index = 1;
            }
            
            if((instruction.operands[mem_index].type == Operand_Type_Register) ||
               (instruction.operands[mem_index].type == Operand_Type_Memory))
            {
                reg_mem = (u8)(instruction.operands[mem_index].reg & 0b0111);
                if((instruction.operands[mem_index].reg & 0b1000) != 0)
                {
                    rex_byte = (u8)(rex_byte | Rex_B);
                }
            }
            
            if(instruction.operands[reg_index].type == Operand_Type_Register)
            {
                
                reg_opcode = (u8)(instruction.operands[reg_index].reg & 0b0111);
                if((instruction.operands[reg_index].reg & 0b1000) != 0)
                {
                    rex_byte = (u8)(rex_byte | Rex_R);
                }
            }
        }
    }
    else if(operation->type == Opcode_Type_Extended)
    {
        
        reg_opcode = operation->extension;
        reg_mem = (u8)(instruction.operands[0].reg & 0b0111);
        if((instruction.operands[0].reg & 0b1000) != 0)
        {
            rex_byte = (u8)(rex_byte | Rex_B);
        }
    }
    else if(operation->type == Opcode_Type_Plus_Register)
    {
        
        // Are these always immediate into register/memory?
        opcode = (u8)(opcode | (instruction.operands[0].reg & 0b0111));
    }
    
    if(rex_byte != 0)
    {
        buffer_append_u8(buffer, rex_byte);
    }
    
    buffer_append_u8(buffer, opcode);
    
    if(operation->use_modrm != 0)
    {
        
        u8 modrm = 0;
        u8 mode = MOD_Registers;
        if((instruction.operands[0].type == Operand_Type_Memory) ||
           (instruction.operands[1].type == Operand_Type_Memory))
        {
            // TODO: need to support memory displacements
            mode = MOD_Pointer;
        }
        
        modrm = (u8)((mode << 6) | (reg_opcode << 3) | (reg_mem << 0));
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

enum Letter_Type
{
    Letter_Type_None,
    Letter_Type_AlphaNumeric,
    Letter_Type_Symbol
};

u32
find_operand
(Operand_Name_List *operand_table, String str)
{
    
    u32 result = 0;
    
    for(u32 index = 0; index < operand_table->count; index++)
    {
        
        Operand_Name *entry = &operand_table->start[index];
        if(entry->name.len == str.len)
        {
            
            b32 match = 1;
            for(u32 ch = 0; ch < str.len; ch++)
            {
                if(entry->name.chars[ch] != str.chars[ch])
                {
                    match = 0;
                    break;
                }
            }
            
            if(match == 1)
            {
                result = index;
                break;
            }
            
        }
    }
    
    return(result);
}

Instruction
parse_line
(Opcode_Name_Table *opcode_table, Operand_Name_List *operand_table, String line)
{
    
    Instruction result = {};
    
#define MAX_WORDS 8
    // TODO: Oh no! Negative numbers won't split correctly.
    String split[MAX_WORDS] = {};
    u32 word = 0;
    Letter_Type letter_type = Letter_Type_None;
    for(u32 i = 0; i < line.len; i++)
    {
        
        Letter_Type prev_letter_type = letter_type;
        
        if((line.chars[i] >= '0') && (line.chars[i] <= '9') ||
           (line.chars[i] >= 'A') && (line.chars[i] <= 'Z') ||
           (line.chars[i] >= 'a') && (line.chars[i] <= 'z'))
        {
            letter_type = Letter_Type_AlphaNumeric;
        }
        else if(line.chars[i] == ' ')
        {
            letter_type = Letter_Type_None;
            continue;
        }
        else
        {
            letter_type = Letter_Type_Symbol;
        }
        
        if(letter_type != Letter_Type_None)
        {
            
            if(prev_letter_type != letter_type)
            {            
                if(split[word].len != 0)
                {
                    
                    word++;
                    Assert(word < MAX_WORDS);
                }
                split[word].chars = &line.chars[i];
            }
            split[word].len++;
        }
    }
    
    u32 operation = 0;
    for(operation = 0; split[operation].len != 0; operation++)
    {
        for(u32 i = 0; i < opcode_table->count; i++)
        {
            Opcode_Name *entry = &opcode_table->start[i];
            if(entry->name.len == split[operation].len)
            {
                
                b32 match = 1;
                for(u32 ch = 0; ch < split[operation].len; ch++)
                {
                    if(entry->name.chars[ch] != split[operation].chars[ch])
                    {
                        match = 0;
                        break;
                    }
                }
                
                if(match != 0)
                {
                    result.opcode = entry->opcode;
                    break;
                }
            }
        }
        
        if(result.opcode != 0)
        {
            break;
        }
    }
    
    if(result.opcode == 0)
    {
        Assert(!"No opcode found.");
    }
    
    if(word > 0)
    {    
        u32 destination = 0;
        for(u32 i = 0; split[i].len != 0; i++)
        {
            if(i != operation)
            {
                destination = i;
                break;
            }
        }
        
        if(word > 1)
        {        
            u32 source = 0;
            for(u32 i = 0; split[i].len != 0; i++)
            {
                if((i != operation) && (i != destination))
                {
                    source = i;
                    break;
                }
            }
            
            if((split[operation].chars[0] == '-') && (split[operation].chars[1] == '>'))
            {
                u32 temp = destination;
                destination = source;
                source = temp;
            }
            
            u32 source_index = find_operand(operand_table, split[source]);
            if(source_index == 0)
            {
                b32 isNumber = check_if_number(split[source]);
                if(isNumber != 0)
                {
                    
                }
                else
                {
                    Assert(!"Unknown operand.");
                }
            }
            else
            {
                result.operands[1] = *(operand_table->start[source_index].operand);
            }
        }
        
        u32 destination_index = find_operand(operand_table, split[destination]);
        if(destination_index == 0)
        {
            
        }
        else
        {
            result.operands[0] = *(operand_table->start[destination_index].operand);
        }
    }
    
    return(result);
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
    
    Buffer buffer_operand_table = create_buffer(PAGE, PAGE_READWRITE);
    Operand_Name_List operand_table = {};
    operand_table.start = (Operand_Name *)buffer_operand_table.end;
    
    Operand no_operand = {};
    String name = {};
    add_operand(&buffer_operand_table, &operand_table, name, &no_operand);
    
    Operand rax = {};
    name = create_string(&buffer_strings, "rax");
    rax = oper(Operand_Type_Register, 0, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &rax);
    
    Operand rcx = {};
    name = create_string(&buffer_strings, "rcx");
    rcx = oper(Operand_Type_Register, 1, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &rcx);
    
    Operand rdx = {};
    name = create_string(&buffer_strings, "rdx");
    rdx = oper(Operand_Type_Register, 2, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &rdx);
    
    Operand rbx = {};
    name = create_string(&buffer_strings, "rbx");
    rbx = oper(Operand_Type_Register, 3, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &rbx);
    
    Operand rsp = {};
    name = create_string(&buffer_strings, "rsp");
    rsp = oper(Operand_Type_Register, 4, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &rsp);
    
    Operand rbp = {};
    name = create_string(&buffer_strings, "rbp");
    rbp = oper(Operand_Type_Register, 5, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &rbp);
    
    Operand rsi = {};
    name = create_string(&buffer_strings, "rsi");
    rsi = oper(Operand_Type_Register, 6, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &rsi);
    
    Operand rdi = {};
    name = create_string(&buffer_strings, "rdi");
    rdi = oper(Operand_Type_Register, 7, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &rdi);
    
    Operand r8 = {};
    name = create_string(&buffer_strings, "r8");
    r8  = oper(Operand_Type_Register, 8, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &r8);
    
    Operand r9 = {};
    name = create_string(&buffer_strings, "r9");
    r9  = oper(Operand_Type_Register, 9, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &r9);
    
    Operand r10 = {};
    name = create_string(&buffer_strings, "r10");
    r10 = oper(Operand_Type_Register, 10, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &r10);
    
    Operand r11 = {};
    name = create_string(&buffer_strings, "r11");
    r11 = oper(Operand_Type_Register, 11, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &r11);
    
    Operand r12 = {};
    name = create_string(&buffer_strings, "r12");
    r12 = oper(Operand_Type_Register, 12, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &r12);
    
    Operand r13 = {};
    name = create_string(&buffer_strings, "r13");
    r13 = oper(Operand_Type_Register, 13, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &r13);
    
    Operand r14 = {};
    name = create_string(&buffer_strings, "r14");
    r14 = oper(Operand_Type_Register, 14, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &r14);
    
    Operand r15 = {};
    name = create_string(&buffer_strings, "r15");
    r15 = oper(Operand_Type_Register, 15, 0, Size_64);
    add_operand(&buffer_operand_table, &operand_table, name, &r15);
    
    Operand eax = {};
    name = create_string(&buffer_strings, "eax");
    eax  = oper(Operand_Type_Register, 0, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &eax);
    
    Operand ecx = {};
    name = create_string(&buffer_strings, "ecx");
    ecx  = oper(Operand_Type_Register, 1, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &ecx);
    
    Operand edx = {};
    name = create_string(&buffer_strings, "edx");
    edx  = oper(Operand_Type_Register, 2, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &edx);
    
    Operand ebx = {};
    name = create_string(&buffer_strings, "ebx");
    ebx  = oper(Operand_Type_Register, 3, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &ebx);
    
    Operand esp = {};
    name = create_string(&buffer_strings, "esp");
    esp  = oper(Operand_Type_Register, 4, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &esp);
    
    Operand ebp = {};
    name = create_string(&buffer_strings, "ebp");
    ebp  = oper(Operand_Type_Register, 5, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &ebp);
    
    Operand esi = {};
    name = create_string(&buffer_strings, "esi");
    esi  = oper(Operand_Type_Register, 6, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &esi);
    
    Operand edi = {};
    name = create_string(&buffer_strings, "edi");
    edi  = oper(Operand_Type_Register, 7, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &edi);
    
    Operand r8d = {};
    name = create_string(&buffer_strings, "r8d");
    r8d  = oper(Operand_Type_Register, 8, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &r8d);
    
    Operand r9d = {};
    name = create_string(&buffer_strings, "r9d");
    r9d  = oper(Operand_Type_Register, 9, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &r9d);
    
    Operand r10d = {};
    name = create_string(&buffer_strings, "r10d");
    r10d = oper(Operand_Type_Register, 10, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &r10d);
    
    Operand r11d = {};
    name = create_string(&buffer_strings, "r11d");
    r11d = oper(Operand_Type_Register, 11, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &r11d);
    
    Operand r12d = {};
    name = create_string(&buffer_strings, "r12d");
    r12d = oper(Operand_Type_Register, 12, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &r12d);
    
    Operand r13d = {};
    name = create_string(&buffer_strings, "r13d");
    r13d = oper(Operand_Type_Register, 13, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &r13d);
    
    Operand r14d = {};
    name = create_string(&buffer_strings, "r14d");
    r14d = oper(Operand_Type_Register, 14, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &r14d);
    
    Operand r15d = {};
    name = create_string(&buffer_strings, "r15d");
    r15d = oper(Operand_Type_Register, 15, 0, Size_32);
    add_operand(&buffer_operand_table, &operand_table, name, &r15d);
    
    Buffer buffer_opcode_table = create_buffer(PAGE, PAGE_READWRITE);
    Buffer buffer_opcode_name_table = create_buffer(PAGE, PAGE_READWRITE);
    Opcode_Name_Table opcode_name_table = {};
    opcode_name_table.start = (Opcode_Name *)buffer_opcode_name_table.end;
    
    Opcode_List mov = {};
    name = create_string(&buffer_strings, "->");
    add_opcode_list(&buffer_opcode_name_table, &opcode_name_table, name, &mov);
    
    add_opcode(&buffer_opcode_table, &mov, 0x88, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_8, Size_8, true, false, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x88, Opcode_Type_Regular, 0, Operand_Type_Memory, Operand_Type_Register, Size_8, Size_8, true, false, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x89, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_32, Size_32, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x89, Opcode_Type_Regular, 0, Operand_Type_Memory, Operand_Type_Register, Size_32, Size_32, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x89, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_64, Size_64, true, false, Reg_Effect_Zero_Extends, Rex_W);
    add_opcode(&buffer_opcode_table, &mov, 0x89, Opcode_Type_Regular, 0, Operand_Type_Memory, Operand_Type_Register, Size_64, Size_64, true, false, Reg_Effect_Zero_Extends, Rex_W);
    add_opcode(&buffer_opcode_table, &mov, 0x8a, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_8, Size_8, true, true, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x8a, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Memory, Size_8, Size_8, true, true, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x8b, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_32, Size_32, true, true, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x8b, Opcode_Type_Regular, 0, Operand_Type_Memory, Operand_Type_Register, Size_32, Size_32, true, true, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0x8b, Opcode_Type_Regular, 0, Operand_Type_Register, Operand_Type_Register, Size_64, Size_64, true, true, Reg_Effect_Zero_Extends, Rex_W);
    add_opcode(&buffer_opcode_table, &mov, 0x8b, Opcode_Type_Regular, 0, Operand_Type_Memory, Operand_Type_Register, Size_64, Size_64, true, true, Reg_Effect_Zero_Extends, Rex_W);
    add_opcode(&buffer_opcode_table, &mov, 0xb0, Opcode_Type_Plus_Register, 0, Operand_Type_Register, Operand_Type_Immediate, Size_8, Size_8, false, false, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0xb8, Opcode_Type_Plus_Register, 0, Operand_Type_Register, Operand_Type_Immediate, Size_32, Size_32, false, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0xb8, Opcode_Type_Plus_Register, 0, Operand_Type_Register, Operand_Type_Immediate, Size_64, Size_64, false, false, Reg_Effect_Zero_Extends, Rex_W);
    add_opcode(&buffer_opcode_table, &mov, 0xc6, Opcode_Type_Extended, 0, Operand_Type_Memory, Operand_Type_Immediate, Size_8, Size_8, true, false, Reg_Effect_Nothing, 0);
    add_opcode(&buffer_opcode_table, &mov, 0xc7, Opcode_Type_Extended, 0, Operand_Type_Memory, Operand_Type_Immediate, Size_32, Size_32, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &mov, 0xc7, Opcode_Type_Extended, 0, Operand_Type_Register, Operand_Type_Immediate, Size_64, Size_32, true, false, Reg_Effect_Sign_Extends, Rex_W);
    add_opcode(&buffer_opcode_table, &mov, 0xc7, Opcode_Type_Extended, 0, Operand_Type_Memory, Operand_Type_Immediate, Size_64, Size_32, true, false, Reg_Effect_Sign_Extends, Rex_W);
    
    Opcode_List add = {};
    name = create_string(&buffer_strings, "add");
    add_opcode_list(&buffer_opcode_name_table, &opcode_name_table, name, &add);
    
    add_opcode(&buffer_opcode_table, &add, 0x83, Opcode_Type_Extended, 0, Operand_Type_Register, Operand_Type_Immediate, Size_32, Size_8, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &add, 0x83, Opcode_Type_Extended, 0, Operand_Type_Memory, Operand_Type_Immediate, Size_32, Size_8, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &add, 0x83, Opcode_Type_Extended, 0, Operand_Type_Register, Operand_Type_Immediate, Size_64, Size_8, true, false, Reg_Effect_Zero_Extends, Rex_W);
    add_opcode(&buffer_opcode_table, &add, 0x83, Opcode_Type_Extended, 0, Operand_Type_Memory, Operand_Type_Immediate, Size_64, Size_8, true, false, Reg_Effect_Zero_Extends, Rex_W);
    
    Opcode_List sub = {};
    name = create_string(&buffer_strings, "sub");
    add_opcode_list(&buffer_opcode_name_table, &opcode_name_table, name, &sub);
    
    add_opcode(&buffer_opcode_table, &sub, 0x83, Opcode_Type_Extended, 5, Operand_Type_Register, Operand_Type_Immediate, Size_32, Size_8, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &sub, 0x83, Opcode_Type_Extended, 5, Operand_Type_Memory, Operand_Type_Immediate, Size_32, Size_8, true, false, Reg_Effect_Zero_Extends, 0);
    add_opcode(&buffer_opcode_table, &sub, 0x83, Opcode_Type_Extended, 5, Operand_Type_Register, Operand_Type_Immediate, Size_64, Size_8, true, false, Reg_Effect_Zero_Extends, Rex_W);
    add_opcode(&buffer_opcode_table, &sub, 0x83, Opcode_Type_Extended, 5, Operand_Type_Memory, Operand_Type_Immediate, Size_64, Size_8, true, false, Reg_Effect_Zero_Extends, Rex_W);
    
    Opcode_List ret = {};
    name = create_string(&buffer_strings, "ret");
    add_opcode_list(&buffer_opcode_name_table, &opcode_name_table, name, &ret);
    
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
        
        String line = create_string(&buffer_strings, "rcx->rax");
        Instruction mov_rax_rcx = parse_line(&opcode_name_table, &operand_table, line);
        assemble(&buffer_functions, mov_rax_rcx);
        
        line = create_string(&buffer_strings, "ret");
        Instruction come_back = parse_line(&opcode_name_table, &operand_table, line);
        assemble(&buffer_functions, come_back);
        
        s64 result = some_number(42);
        Assert(result == 42);
    }
    
    {
        fn_void_to_s32 the_answer = (fn_void_to_s32)buffer_functions.end;
        
        String line = create_string(&buffer_strings, "42->rax");
        Instruction mov_imm = parse_line(&opcode_name_table, &operand_table, line);
        
        Operand imm64 = oper(Operand_Type_Immediate, 0, 42, Size_64);
        
        assemble(&buffer_functions, inst(&mov, rax, imm64));
        assemble(&buffer_functions, inst(&ret, no_operand, no_operand));
        
        s64 result = the_answer();
        Assert(result == 42);
    }
    
    {
        fn_s64_to_void write_to_pointer  = (fn_s64_to_void)buffer_functions.end;
        
        Operand imm64 = oper(Operand_Type_Immediate, 0, 42, Size_64);
        Operand pointer_rcx = oper(Operand_Type_Memory, rcx.reg, 0, Size_64);
        
        assemble(&buffer_functions, inst(&mov, rax, imm64));
        assemble(&buffer_functions, inst(&mov, pointer_rcx, rax));
        assemble(&buffer_functions, inst(&ret, no_operand, no_operand));
        
        write_to_pointer((s64)buffer_junk.memory);
        Assert(*(s64 *)buffer_junk.memory == 42);
    }
    
    {
        fn_s64_to_s64 not_the_answer = (fn_s64_to_s64)buffer_functions.end;
        
        Operand imm8 = oper(Operand_Type_Immediate, 0, 1, Size_8);
        
        assemble(&buffer_functions, inst(&sub, rcx, imm8));
        assemble(&buffer_functions, inst(&mov, r8, rcx));
        assemble(&buffer_functions, inst(&add, r8, imm8));
        assemble(&buffer_functions, inst(&mov, rax, rcx));
        assemble(&buffer_functions, inst(&ret, no_operand, no_operand));
        
        s64 result = not_the_answer(42);
        Assert(result == 41);
    }
    
    ExitProcess(0);
}