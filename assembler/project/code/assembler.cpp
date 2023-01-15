/* TODO: There's a few things to do to get my program somewhere that can call
*        a windows function
*
*    rsp - STACK_ADJUST
*    string winString "Hello, World!\0"
*    winString &-> rcx
*    call kernell32.dll:OutputDebugStringA
*    eax <- 0
*    rsp + STACK_ADJUST
*    ret
*
*    lea instruction based on rip
*    - implement variables
*      - dynamic array of variable names
*      - variable to keep track of stack adjustment amount
*    - add lea instruction
*    - improve test's ability to support the resource section
*    - improve assembler's ability to support the resource section
*
*    call a function pointer based on rip
*    - window's loader is going to put the function address in my program
*/

#include "win64_assembler.h"

typedef void (*fn_void_to_void)();
typedef u32 (*fn_void_to_u32)();
typedef u64 (*fn_void_to_u64)();

#define REX   0x40
#define REX_W 0x08
#define REX_R 0x04
#define REX_X 0x02
#define REX_B 0x01

enum list_entry_type
{
	none,
	ret,
	mov_left,
	mov_right,
	add,
	sub,
	reg,
	imm,
	string,
};

struct list_entry
{
	list_entry_type type;
	String name;
	u8 size;
	u8 opcode_extension;
	u8 reg_address;
	u64 imm_value;
};

struct reserved_list
{
	list_entry *start;
	u32 count;
	Buffer reserved;
	Buffer strings;
};

void
add_to_list
(reserved_list *list, char *str, list_entry_type type, u8 size, u8 opcode_extension, u8 reg_address, u64 imm_value)
{
	
	list_entry *temp = (list_entry *)buffer_allocate(&list->reserved, sizeof(list_entry));
	list->count++;
	temp->name = create_string(&list->strings, str);
	temp->type = type;
	temp->size = size;
	temp->opcode_extension = opcode_extension;
	temp->reg_address = reg_address;
	temp->imm_value = imm_value;
}

global reserved_list Reserved_Strings;

void
ReserveStrings
(void)
{
	Reserved_Strings.start = (list_entry *)Reserved_Strings.reserved.memory;
	
	/* OPCODES */
	add_to_list(&Reserved_Strings, "->", mov_right, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "<-", mov_left, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "ret", ret, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "+", add, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "-", sub, 0, 0b101, 0, 0);
	
	/* REGISTERS */
	add_to_list(&Reserved_Strings, "eax", reg, size_32, 0, 0, 0);
	add_to_list(&Reserved_Strings, "ecx", reg, size_32, 0, 1, 0);
	add_to_list(&Reserved_Strings, "edx", reg, size_32, 0, 2, 0);
	add_to_list(&Reserved_Strings, "ebx", reg, size_32, 0, 3, 0);
	add_to_list(&Reserved_Strings, "esp", reg, size_32, 0, 4, 0);
	add_to_list(&Reserved_Strings, "ebp", reg, size_32, 0, 5, 0);
	add_to_list(&Reserved_Strings, "esi", reg, size_32, 0, 6, 0);
	add_to_list(&Reserved_Strings, "edi", reg, size_32, 0, 7, 0);
	
	add_to_list(&Reserved_Strings, "r8d", reg, size_32, 0, 8, 0);
	add_to_list(&Reserved_Strings, "r9d", reg, size_32, 0, 9, 0);
	add_to_list(&Reserved_Strings, "r10d", reg, size_32, 0, 10, 0);
	add_to_list(&Reserved_Strings, "r11d", reg, size_32, 0, 11, 0);
	add_to_list(&Reserved_Strings, "r12d", reg, size_32, 0, 12, 0);
	add_to_list(&Reserved_Strings, "r13d", reg, size_32, 0, 13, 0);
	add_to_list(&Reserved_Strings, "r14d", reg, size_32, 0, 14, 0);
	add_to_list(&Reserved_Strings, "r15d", reg, size_32, 0, 15, 0);
	
	add_to_list(&Reserved_Strings, "rax", reg, size_64, 0, 0, 0);
	add_to_list(&Reserved_Strings, "rcx", reg, size_64, 0, 1, 0);
	add_to_list(&Reserved_Strings, "rdx", reg, size_64, 0, 2, 0);
	add_to_list(&Reserved_Strings, "rbx", reg, size_64, 0, 3, 0);
	add_to_list(&Reserved_Strings, "rsp", reg, size_64, 0, 4, 0);
	add_to_list(&Reserved_Strings, "rbp", reg, size_64, 0, 5, 0);
	add_to_list(&Reserved_Strings, "rsi", reg, size_64, 0, 6, 0);
	add_to_list(&Reserved_Strings, "rdi", reg, size_64, 0, 7, 0);
	
	add_to_list(&Reserved_Strings, "r8", reg, size_64, 0, 8, 0);
	add_to_list(&Reserved_Strings, "r9", reg, size_64, 0, 9, 0);
	add_to_list(&Reserved_Strings, "r10", reg, size_64, 0, 10, 0);
	add_to_list(&Reserved_Strings, "r11", reg, size_64, 0, 11, 0);
	add_to_list(&Reserved_Strings, "r12", reg, size_64, 0, 12, 0);
	add_to_list(&Reserved_Strings, "r13", reg, size_64, 0, 13, 0);
	add_to_list(&Reserved_Strings, "r14", reg, size_64, 0, 14, 0);
	add_to_list(&Reserved_Strings, "r15", reg, size_64, 0, 15, 0);
	
	/* VARIABLE TYPES */
	add_to_list(&Reserved_Strings, "string", string, 0, 0, 0, 0);
}

struct Instruction
{
	list_entry operation;
	list_entry operands[2];
};

void
swap_operands
(Instruction *instruction)
{
	
	list_entry temp = instruction->operands[0];
	instruction->operands[0] = instruction->operands[1];
	instruction->operands[1] = temp;
}

void
assemble
(Buffer *program, Buffer *Memory, String src)
{
	U8_Array *header = (U8_Array *)(buffer_allocate(program, (2 * sizeof(U8_Array))));
	Buffer byte_code = create_buffer(program, 64);
	Buffer resource = create_buffer(program, 64);
	
	b8 *IsInitialized = (b8 *)Memory->memory;
	if(*IsInitialized == FALSE)
	{
		// NOTE: Need to reserve space for IsInitialized
		buffer_allocate(Memory, size_8);
		
		Reserved_Strings.strings = create_buffer(Memory, 1024);
		Reserved_Strings.reserved = create_buffer(Memory, 2048);
		ReserveStrings();
		*IsInitialized = TRUE;
	}
	
	Instruction instr = {};
	b32 InstructionComplete = FALSE;
	String token = {};
	b32 CompleteToken = FALSE;
	u64 EndOfFile = src.len - 1;
	u32 CurrentOperand = 0;
	
	b32 processString = FALSE;
	u8 *StringChars = 0;
	u64 *StringLen = 0;
	
	b32 processVariableName = FALSE;
	list_entry *newEntry = 0;
	for(u64 i = 0; i <= EndOfFile; i++)
	{
		if(processString == FALSE)
		{
			
			if(IsWhiteSpace(src.chars[i]) == TRUE)
			{
				CompleteToken = (token.chars == 0) ? FALSE : TRUE;
			}
			else if(src.chars[i] == '"')
			{
				processString = TRUE;
				
				if(StringChars == 0)
				{
					StringLen = (u64 *)buffer_allocate(&resource, size_64);
					StringChars = resource.end;
				}
				
			}
			else
			{
				
				if(i == EndOfFile)
				{
					CompleteToken = (token.chars == 0) ? FALSE : TRUE;
				}
				
				if(token.chars == 0)
				{
					token.chars = &src.chars[i];
				}
				
				token.len++;
			}
		}
		else if(processString == TRUE)
		{
			
			if(src.chars[i] != '"')
			{
				if(src.chars[i] == '\\')
				{
					
					Assert((i + 1) <= EndOfFile);
					i++;
					if(src.chars[i] == '0')
					{
						buffer_append_u8(&resource, 0);
						
					}
					else if(src.chars[i] == '\\')
					{
						buffer_append_u8(&resource, '\\');
					}
					else if(src.chars[i] == '"')
					{
						buffer_append_u8(&resource, '"');
					}
					
					(*StringLen)++;
				}
				else
				{
					
					buffer_append_u8(&resource, src.chars[i]);
					(*StringLen)++;
				}
			}
			else if(src.chars[i] == '"')
			{
				
				processString = FALSE;
			}
		}
		
		if(CompleteToken == TRUE)
		{		
			if(IsNumber(token) == TRUE)
			{
				
				list_entry *operand = &instr.operands[CurrentOperand++];
				operand->name = token;
				operand->type = imm;
				operand->imm_value = StringToU64(token);
				if((CurrentOperand == 2) && (instr.operation.type != none))
				{
					InstructionComplete = TRUE;
				}
				
			}
			else if(processVariableName == TRUE)
			{
				
				Assert(newEntry != 0);
				newEntry->name = token;
				processVariableName = FALSE;
				
			}
			else
			{
				for(u32 n = 0; n < Reserved_Strings.count; n++)
				{
					
					list_entry *entry = &Reserved_Strings.start[n];
					if(token == entry->name)
					{
						
						if(entry->type == reg)
						{
							instr.operands[CurrentOperand++] = *entry;
							if((CurrentOperand == 2) && (instr.operation.type != none))
							{
								InstructionComplete = TRUE;
							}
							
						}
						else if(entry->type == string)
						{
							processVariableName = TRUE;
							newEntry = (list_entry *)buffer_allocate(&Reserved_Strings.reserved, sizeof(list_entry));
							Reserved_Strings.count++;
							newEntry->type = string;
						}
						else
						{
							
							instr.operation = *entry;
						}
						
						if(entry->type == ret)
						{
							InstructionComplete = TRUE;
						}
						
						break;
					}
				}
			}
			
			if(InstructionComplete == TRUE)
			{
				u8 op_code = 0;
				b32 useModrm = FALSE;
				u8 modrm = 0;
				
				switch (instr.operation.type)
				{
				  case ret:
					{
						
						op_code = 0xc3;
					}break;
					
					case sub:
				  case add:
					{
						
						if(instr.operands[0].type == imm)
						{
							swap_operands(&instr);
						}
						if(instr.operands[1].type == imm)
						{
							instr.operands[1].size = size_8;
						}
						
						op_code = 0x83;
						
						u8 reg_op = (u8)(instr.operation.opcode_extension & 0b0111);
						u8 reg_mem = (u8)(instr.operands[0].reg_address & 0b0111);
						modrm = (u8)(0xc0 | (reg_op << 3) | reg_mem);
						useModrm = TRUE;
						
					}break;
					
					case mov_right:
					{
						swap_operands(&instr);
					}; // NOTE: Fall through to mov_left.
					case mov_left:
					{
						if(instr.operands[1].type == imm)
						{
							
							op_code = (u8)(0xb8 | (instr.operands[0].reg_address & 0b0111));
							instr.operands[1].size = instr.operands[0].size;
						}
						else
						{
							op_code = 0x89;
							
							u8 reg_op = (u8)(instr.operands[1].reg_address & 0b0111);
							u8 reg_mem = (u8)(instr.operands[0].reg_address & 0b0111);
							modrm = (u8)(0xc0 | (reg_op << 3) | reg_mem);
							useModrm = TRUE;
						}
						
					}break;
				}
				
				u8 rex = 0;
				if((instr.operands[0].size == sizeof(u64)) || (instr.operands[1].size == sizeof(u64)))
				{
					rex = REX | REX_W;
				}
				
				if(instr.operands[0].reg_address > 7)
				{
					rex = (u8)(rex | REX | REX_B);
				}
				if(instr.operands[1].reg_address > 7)
				{
					rex = (u8)(rex | REX | REX_R);
				}
				
				if(rex != 0)
				{
					buffer_append_u8(&byte_code, rex);
				}
				
				buffer_append_u8(&byte_code, op_code);
				
				if(useModrm == TRUE)
				{
					buffer_append_u8(&byte_code, modrm);
				}
				
				if(instr.operands[1].type == imm)
				{
					if(instr.operands[1].size == size_8)
					{
						
						buffer_append_u8(&byte_code, (u8)instr.operands[1].imm_value);
					}
					else if(instr.operands[1].size == size_16)
					{
						
						buffer_append_u16(&byte_code, (u16)instr.operands[1].imm_value);
					}
					else if(instr.operands[1].size == size_32)
					{
						
						buffer_append_u32(&byte_code, (u32)instr.operands[1].imm_value);
					}
					else if(instr.operands[1].size == size_64)
					{
						
						buffer_append_u64(&byte_code, instr.operands[1].imm_value);
					}
				}
				
				CurrentOperand = 0;
				instr = {};
				InstructionComplete = FALSE;
			}
			
			CompleteToken = FALSE;
			token = {};
		}
	}
	
	header[0].bytes = byte_code.memory;
	header[0].len = (u64)(byte_code.end - byte_code.memory);
	header[1].bytes = resource.memory;
	header[1].len = (u64)(resource.end - resource.memory);
}
