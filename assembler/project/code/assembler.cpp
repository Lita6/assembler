#include "win64_assembler.h"

typedef void (*fn_void_to_void)();
typedef u32 (*fn_void_to_u32)();

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
	u64 value;
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
	add_to_list(reserved, strings, &Reserved_Strings, "eax", reg, 0);
	add_to_list(reserved, strings, &Reserved_Strings, "ret", ret, 0);
	
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
	// TODO: token can go back to being a string because if it's identified as an operand then the instr can be filled out instead
	
	Instruction instr = {};
	b32 InstructionComplete = FALSE;
	list_entry token = {};
	b32 CompleteToken = FALSE;
	u64 EndOfFile = src.len - 1;
	for(u64 i = 0; i < src.len; i++)
	{
		
		if(IsWhiteSpace(src.chars[i]) == TRUE)
		{
			CompleteToken = (token.name.chars == 0) ? FALSE : TRUE;
		}
		else
		{
			
			if(i == EndOfFile)
			{
				CompleteToken = (token.name.chars == 0) ? FALSE : TRUE;
			}
			
			if(token.name.chars == 0)
			{
				token.name.chars = &src.chars[i];
			}
			
			token.name.len++;
		}
		
		if(CompleteToken == TRUE)
		{		
			if(IsNumber(token.name.chars[0]) == TRUE)
			{
				token.type = imm;
			}
			
			if(token.type != imm)
			{
				for(u32 n = 0; n < Reserved_Strings.count; n++)
				{
					
					list_entry *entry = &Reserved_Strings.start[n];
					if(token.name.chars[0] == entry->name.chars[0])
					{
						
						if(entry->type == ret)
						{
							instr.operation = *entry;
							InstructionComplete = TRUE;
						}
						
						break;
					}
				}
			}
			
			if(InstructionComplete == TRUE)
			{
				if(instr.operation.type == ret)
				{
					
					buffer_append_u8(byte_code, 0xc3);
					instr = {};
					InstructionComplete = FALSE;
				}
			}
			
			CompleteToken = FALSE;
			token = {};
		}
	}
	
}
