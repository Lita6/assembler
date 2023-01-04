/* TODO: There's a few things to do to get my program somewhere that can call
*        a windows function
*
*    sub an immediate from rsp
*    add an immediate to rsp
*    - add instruction
*    - sub instruction
*    - MODRM bit
*    - operand sizing
*
*    lea instruction based on rip
*    - because I need an address to a string from within my program
*    call a function pointer based on rip
*    - window's loader is going to put the function address in my program
*/

#include "win64_assembler.h"

typedef void (*fn_void_to_void)();
typedef u32 (*fn_void_to_u32)();

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
	reg,
	imm,
};

struct list_entry
{
	list_entry_type type;
	String name;
	u64 value; // NOTE: storing imm numbers and reg addresses
};

struct reserved_list
{
	list_entry *start;
	u32 count;
};

void
add_to_list
(Buffer *list_buffer, Buffer *strings, reserved_list *list, char *str, list_entry_type type, u64 value)
{
	
	list_entry *temp = (list_entry *)buffer_allocate(list_buffer, sizeof(list_entry));
	list->count++;
	temp->name = create_string(strings, str);
	temp->type = type;
	temp->value = value;
}

global reserved_list Reserved_Strings;

void
init
(Buffer *reserved, Buffer *strings)
{
	Reserved_Strings.start = (list_entry *)reserved->memory;
	
	add_to_list(reserved, strings, &Reserved_Strings, "->", mov_right, 0);
	add_to_list(reserved, strings, &Reserved_Strings, "<-", mov_left, 0);
	add_to_list(reserved, strings, &Reserved_Strings, "ret", ret, 0);
	
	/* REGISTERS */
	add_to_list(reserved, strings, &Reserved_Strings, "eax", reg, 0);
	add_to_list(reserved, strings, &Reserved_Strings, "ecx", reg, 1);
	add_to_list(reserved, strings, &Reserved_Strings, "edx", reg, 2);
	add_to_list(reserved, strings, &Reserved_Strings, "ebx", reg, 3);
	add_to_list(reserved, strings, &Reserved_Strings, "esp", reg, 4);
	add_to_list(reserved, strings, &Reserved_Strings, "ebp", reg, 5);
	add_to_list(reserved, strings, &Reserved_Strings, "esi", reg, 6);
	add_to_list(reserved, strings, &Reserved_Strings, "edi", reg, 7);
	
	add_to_list(reserved, strings, &Reserved_Strings, "r8d", reg, 8);
	add_to_list(reserved, strings, &Reserved_Strings, "r9d", reg, 9);
	add_to_list(reserved, strings, &Reserved_Strings, "r10d", reg, 10);
	add_to_list(reserved, strings, &Reserved_Strings, "r11d", reg, 11);
	add_to_list(reserved, strings, &Reserved_Strings, "r12d", reg, 12);
	add_to_list(reserved, strings, &Reserved_Strings, "r13d", reg, 13);
	add_to_list(reserved, strings, &Reserved_Strings, "r14d", reg, 14);
	add_to_list(reserved, strings, &Reserved_Strings, "r15d", reg, 15);
	
}

struct Instruction
{
	list_entry operation;
	list_entry operands[2];
};

void
assemble
(Buffer *byte_code, String src)
{
	
	Instruction instr = {};
	b32 InstructionComplete = FALSE;
	String token = {};
	b32 CompleteToken = FALSE;
	u64 EndOfFile = src.len - 1;
	u32 CurrentOperand = 0;
	for(u64 i = 0; i < src.len; i++)
	{
		
		if(IsWhiteSpace(src.chars[i]) == TRUE)
		{
			CompleteToken = (token.chars == 0) ? FALSE : TRUE;
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
		
		if(CompleteToken == TRUE)
		{		
			if(IsNumber(token) == TRUE)
			{
				
				list_entry *operand = &instr.operands[CurrentOperand++];
				operand->name = token;
				operand->type = imm;
				operand->value = StringToU64(token);
				if((CurrentOperand == 2) && (instr.operation.type != none))
				{
					InstructionComplete = TRUE;
				}
				
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
				
				switch (instr.operation.type)
				{
				  case ret:
					{
						
						buffer_append_u8(byte_code, 0xc3);
						instr = {};
						InstructionComplete = FALSE;
						
					}break;
					
					case mov_right:
					{
						list_entry temp = instr.operands[0];
						instr.operands[0] = instr.operands[1];
						instr.operands[1] = temp;
						
					}; // NOTE: Fall through to move_left
					case mov_left:
					{
						
						if(instr.operands[0].value > 7)
						{
							u8 rex = REX | REX_B;
							buffer_append_u8(byte_code, rex);
						}
						
						u8 op = (u8)(0xb8 | (instr.operands[0].value & 0b0111));
						buffer_append_u8(byte_code, op);
						buffer_append_u32(byte_code, (u32)instr.operands[1].value);
						
						instr = {};
						InstructionComplete = FALSE;
						CurrentOperand = 0;
						
					}break;
				}
			}
			
			CompleteToken = FALSE;
			token = {};
		}
	}
	
}
