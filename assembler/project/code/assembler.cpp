/* TODO: 
*
*    - implement variables
*      - memory to reg move
*    - implement addressing modes 
*      - e.g. There's a huge difference between "call rax" and "call qword ptr[rax]"
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
	lea_left,
	lea_right,
	call,
	string_word,
	u64_word,
	label_word,
	reg,
	imm,
	string,
	import_function,
	u64_type,
	label,
};

struct list_entry
{
	list_entry_type type;
	list_entry *variable_entry;
	String name;
	u8 size;
	u8 opcode_extension;
	u8 reg_address;
	u64 imm_value;
	s32 resource_offset;
	u8 stack_offset;
	s32 bytecode_offset;
};

struct Patch
{
	list_entry *variable_entry;
	u8 *location;
};

struct Patch_Array
{
	Patch *start;
	u32 count;
};

struct reserved_list
{
	list_entry *start;
	u32 count;
	Buffer reserved;
	u8 *temp_entry_start;
	Buffer strings;
};

void
DeallocateOffEnd
(Buffer *buffer, u8 *start)
{
	Assert((start >= buffer->memory) && (start <= buffer->end));
	
	for(u8 *i = start; i < buffer->end; i++)
	{
		*i = 0;
	}
	
	buffer->end = start;
}

void
add_to_list
(reserved_list *list, char *str, list_entry_type type, u8 size, u8 opcode_extension, u8 reg_address, s32 resource_offset, u64 imm_value)
{
	
	list_entry *temp = (list_entry *)buffer_allocate(&list->reserved, sizeof(list_entry));
	list->count++;
	
	temp->name = create_string(&list->strings, str);
	temp->type = type;
	temp->size = size;
	temp->opcode_extension = opcode_extension;
	temp->reg_address = reg_address;
	temp->imm_value = imm_value;
	temp->resource_offset = resource_offset;
	
}

global reserved_list Reserved_Strings;

void
ReserveStrings
(void)
{
	Reserved_Strings.start = (list_entry *)Reserved_Strings.reserved.memory;
	
	/* OPCODES */
	add_to_list(&Reserved_Strings, "->", mov_right, 0, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "<-", mov_left, 0, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "ret", ret, 0, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "+", add, 0, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "-", sub, 0, 0b101, 0, 0, 0);
	add_to_list(&Reserved_Strings, "<-&", lea_left, 0, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "&->", lea_right, 0, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "call", call, 0, 0b010, 0, 0, 0);
	
	/* REGISTERS */
	add_to_list(&Reserved_Strings, "eax", reg, size_32, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "ecx", reg, size_32, 0, 1, 0, 0);
	add_to_list(&Reserved_Strings, "edx", reg, size_32, 0, 2, 0, 0);
	add_to_list(&Reserved_Strings, "ebx", reg, size_32, 0, 3, 0, 0);
	add_to_list(&Reserved_Strings, "esp", reg, size_32, 0, 4, 0, 0);
	add_to_list(&Reserved_Strings, "ebp", reg, size_32, 0, 5, 0, 0);
	add_to_list(&Reserved_Strings, "esi", reg, size_32, 0, 6, 0, 0);
	add_to_list(&Reserved_Strings, "edi", reg, size_32, 0, 7, 0, 0);
	
	add_to_list(&Reserved_Strings, "r8d", reg, size_32, 0, 8, 0, 0);
	add_to_list(&Reserved_Strings, "r9d", reg, size_32, 0, 9, 0, 0);
	add_to_list(&Reserved_Strings, "r10d", reg, size_32, 0, 10, 0, 0);
	add_to_list(&Reserved_Strings, "r11d", reg, size_32, 0, 11, 0, 0);
	add_to_list(&Reserved_Strings, "r12d", reg, size_32, 0, 12, 0, 0);
	add_to_list(&Reserved_Strings, "r13d", reg, size_32, 0, 13, 0, 0);
	add_to_list(&Reserved_Strings, "r14d", reg, size_32, 0, 14, 0, 0);
	add_to_list(&Reserved_Strings, "r15d", reg, size_32, 0, 15, 0, 0);
	
	add_to_list(&Reserved_Strings, "rax", reg, size_64, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "rcx", reg, size_64, 0, 1, 0, 0);
	add_to_list(&Reserved_Strings, "rdx", reg, size_64, 0, 2, 0, 0);
	add_to_list(&Reserved_Strings, "rbx", reg, size_64, 0, 3, 0, 0);
	add_to_list(&Reserved_Strings, "rsp", reg, size_64, 0, 4, 0, 0);
	add_to_list(&Reserved_Strings, "rbp", reg, size_64, 0, 5, 0, 0);
	add_to_list(&Reserved_Strings, "rsi", reg, size_64, 0, 6, 0, 0);
	add_to_list(&Reserved_Strings, "rdi", reg, size_64, 0, 7, 0, 0);
	
	add_to_list(&Reserved_Strings, "r8", reg, size_64, 0, 8, 0, 0);
	add_to_list(&Reserved_Strings, "r9", reg, size_64, 0, 9, 0, 0);
	add_to_list(&Reserved_Strings, "r10", reg, size_64, 0, 10, 0, 0);
	add_to_list(&Reserved_Strings, "r11", reg, size_64, 0, 11, 0, 0);
	add_to_list(&Reserved_Strings, "r12", reg, size_64, 0, 12, 0, 0);
	add_to_list(&Reserved_Strings, "r13", reg, size_64, 0, 13, 0, 0);
	add_to_list(&Reserved_Strings, "r14", reg, size_64, 0, 14, 0, 0);
	add_to_list(&Reserved_Strings, "r15", reg, size_64, 0, 15, 0, 0);
	
	/* VARIABLE TYPES */
	add_to_list(&Reserved_Strings, "string", string_word, 0, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "u64", u64_word, 0, 0, 0, 0, 0);
	add_to_list(&Reserved_Strings, "label", label_word, 0, 0, 0, 0, 0);
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
StuffStringIntoArray
(u8 *array, char *str, u32 len)
{
	
	u8 *index = (u8 *)str;
	for(u32 i = 0; i < len; i++)
	{
		if(index[i] == 0)
		{
			break;
		}
		
		array[i] = index[i];
	}
}

#define KERNEL32_NAME_LEN 14
#define LOADLIBRARY_NAME_LEN 14
#define GETPROC_NAME_LEN 16

#pragma pack(push, 1)
struct Import_Data_Table
{
	u64 load_lib_address;
	u64 get_proc_address;
	u64 iat_null;
	u64 load_lib_lookup;
	u64 get_proc_lookup;
	u64 ilt_null;
	u32 ILT_RVA;
	u32 timeStamp;
	u32 forwarderChain;
	u32 nameRVA;
	u32 IAT_RVA;
	u32 ILT_RVA_null;
	u32 timeStamp_null;
	u32 forwarderChain_null;
	u32 nameRVA_null;
	u32 IAT_RVA_null;
	u8 kernel32_name[KERNEL32_NAME_LEN];
	u16 loadlibrary_hint;
	u8 loadlibrary_name[LOADLIBRARY_NAME_LEN];
	u16 getproc_hint;
	u8 getproc_name[GETPROC_NAME_LEN];
};
#pragma pack(pop)

b32
IsComplete
(Instruction instr, u32 CurrentOperand)
{
	b32 result = FALSE;
	
	if(((CurrentOperand == 2) || (instr.operation.type == call)) && (instr.operation.type != none))
	{
		result = TRUE;
	}
	
	return(result);
}

b32
FillOperand
(Instruction *instr, list_entry *entry, u32 *CurrentOperand)
{
	
	instr->operands[(*CurrentOperand)] = *entry;
	instr->operands[(*CurrentOperand)].variable_entry = entry;
	(*CurrentOperand)++;
	
	b32 result = IsComplete(*instr, *CurrentOperand);
	return(result);
}

void
assemble
(Buffer *program, Buffer *Memory, String src, u32 PAGE)
{
	
	U8_Array *header = (U8_Array *)(buffer_allocate(program, (2 * sizeof(U8_Array))));
	Buffer byte_code = create_buffer(program, 200);
	Buffer resource = create_buffer(program, 400);
	Import_Data_Table *import_table = (Import_Data_Table *)(buffer_allocate(&resource, sizeof(Import_Data_Table)));
	
	u32 loadlibrary_offset = (u32)((u8 *)(&import_table->load_lib_address) - resource.memory);
	
	import_table->ILT_RVA = (u32)((u8 *)(&import_table->load_lib_lookup) - resource.memory) + PAGE*2;
	u32 kernel32_name_offset = (u32)(import_table->kernel32_name - resource.memory);
	import_table->nameRVA = kernel32_name_offset + PAGE*2;
	import_table->IAT_RVA = loadlibrary_offset + PAGE*2;
	
	u32 loadlibrary_RVA = (u32)((u8 *)(&import_table->loadlibrary_hint) - resource.memory) + PAGE*2;
	import_table->load_lib_address = import_table->load_lib_lookup = loadlibrary_RVA;
	
	u32 getproc_RVA = (u32)((u8 *)(&import_table->getproc_hint) - resource.memory) + PAGE*2;
	import_table->get_proc_address = import_table->get_proc_lookup = getproc_RVA;
	
	StuffStringIntoArray(import_table->kernel32_name, "KERNEL32.dll", KERNEL32_NAME_LEN);
	StuffStringIntoArray(import_table->loadlibrary_name, "LoadLibraryA", LOADLIBRARY_NAME_LEN);
	StuffStringIntoArray(import_table->getproc_name, "GetProcAddress", GETPROC_NAME_LEN);
	
	list_entry *stack_entry = 0;
	b8 *IsInitialized = (b8 *)Memory->memory;
	if(*IsInitialized == FALSE)
	{
		// NOTE: Need to reserve space for IsInitialized
		buffer_allocate(Memory, size_8);
		
		Reserved_Strings.strings = create_buffer(Memory, 1024);
		Reserved_Strings.reserved = create_buffer(Memory, 1024*4);
		ReserveStrings();
		
		add_to_list(&Reserved_Strings, "kernel32_name", string, size_32, 0, 0, (s32)kernel32_name_offset, 0);
		add_to_list(&Reserved_Strings, "LoadLibraryA", import_function, size_32, 0, 0b101, (s32)loadlibrary_offset, 0);
		add_to_list(&Reserved_Strings, "GetProcAddress", import_function, size_32, 0, 0b101, (s32)((u8 *)(&import_table->get_proc_address) - resource.memory), 0);
		add_to_list(&Reserved_Strings, "STACK_ADJUST", imm, size_8, 0, 0, 0, 0);
		
		*IsInitialized = TRUE;
	}
	
	Reserved_Strings.temp_entry_start = Reserved_Strings.reserved.end;
	
	// NOTE: Need to reset stack_entry every time for testing
	stack_entry = &Reserved_Strings.start[(Reserved_Strings.count-1)];
	u64 return_address_size = size_64;
	u64 shadow_stack_size = (u64)(size_64 * 4);
	stack_entry->imm_value = return_address_size + shadow_stack_size;
	
	Buffer buffer_patches = create_buffer(Memory, 1024);
	Patch_Array patches = {};
	patches.start = (Patch *)buffer_patches.memory;
	
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
	
	b32 create_stack_patch = FALSE;
	for(u64 i = 0; i <= EndOfFile; i++)
	{
		if(processString == FALSE)
		{
			
			if(IsWhiteSpace(src.chars[i]) == TRUE)
			{
				CompleteToken = (token.chars == 0) ? FALSE : TRUE;
				
				if((src.chars[i] == '\r') || (src.chars[i] == '\n'))
				{
					if(newEntry != 0)
					{
						if(StringChars != 0)
						{
							newEntry->resource_offset = (s32)(StringChars - resource.memory);
							StringChars = 0;
							StringLen = 0;
						}
						
						newEntry = 0;
					}
				}
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
			else if(src.chars[i] == ':')
			{
				list_entry *entry = instr.operands[0].variable_entry;
				entry->bytecode_offset = (s32)(byte_code.end - byte_code.memory);
				instr = {};
				CurrentOperand = 0;
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
					else if(src.chars[i] == 'n')
					{
						buffer_append_u8(&resource, '\n');
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
				
				InstructionComplete = IsComplete(instr, CurrentOperand);
				
			}
			else if(processVariableName == TRUE)
			{
				
				Assert(newEntry != 0);
				newEntry->name = token;
				processVariableName = FALSE;
				
				if(newEntry->type != string)
				{
					InstructionComplete = FillOperand(&instr, newEntry, &CurrentOperand);
				}
				
			}
			else
			{
				for(u32 n = 0; n < Reserved_Strings.count; n++)
				{
					
					list_entry *entry = &Reserved_Strings.start[n];
					if(token == entry->name)
					{
						
						if((entry->type == reg) || (entry->type == string) || (entry->type == import_function) || (entry->type == imm) || (entry->type == label) || (entry->type == u64_type))
						{
							if(entry == stack_entry)
							{
								create_stack_patch = TRUE;
							}
							
							InstructionComplete = FillOperand(&instr, entry, &CurrentOperand);
							
						}
						else if((entry->type == string_word) || (entry->type == u64_word) || (entry->type == label_word))
						{
							processVariableName = TRUE;
							newEntry = (list_entry *)buffer_allocate(&Reserved_Strings.reserved, sizeof(list_entry));
							Reserved_Strings.count++;
							
							if((entry->type == string_word) || (entry->type == label_word))
							{
								newEntry->type = (entry->type == string_word) ? string : label;
								newEntry->size = size_32;
							}
							else if(entry->type == u64_word)
							{
								newEntry->type = u64_type;
								newEntry->size = size_64;
								newEntry->stack_offset = (u8)(stack_entry->imm_value);
								
								stack_entry->imm_value += size_64;
								Assert(stack_entry->imm_value < 256);
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
				u8 op_code = 0;
				b32 useModrm = FALSE;
				u8 modrm = 0;
				b32 useSIB = FALSE;
				u8 SIB = 0;
				b32 useDisplacement = FALSE;
				u32 Displacement = 0;
				u8 DisplacementSize = 0;
				
				switch (instr.operation.type)
				{
				  case ret:
					{
						op_code = 0xc3;
					}break;
					
				  case call:
					{
						op_code = 0xff;
						
						u8 mode = 0;
						if(instr.operands[0].type == reg)
						{
							mode = 0b11;
						}
						
						useModrm = TRUE;
						modrm = (u8)((mode << 6) | (instr.operation.opcode_extension << 3) | (instr.operands[0].reg_address & 0b111));
						
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
							// TODO: Determine size if there is none
							instr.operands[1].size = size_8;
						}
						
						op_code = 0x83;
						
						u8 reg_op = (u8)(instr.operation.opcode_extension & 0b0111);
						u8 reg_mem = (u8)(instr.operands[0].reg_address & 0b0111);
						modrm = (u8)(0xc0 | (reg_op << 3) | reg_mem);
						useModrm = TRUE;
						
					}break;
					
					case lea_right:
					{
						swap_operands(&instr);
					}; // NOTE: Fall through to lea_left.
					case lea_left:
					{
						op_code = 0x8d;
						
						u8 reg_op = (u8)(instr.operands[0].reg_address & 0b0111);
						modrm = (u8)(0x00 | (reg_op << 3) | 0b101);
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
							
							Assert(instr.operands[1].size <= instr.operands[0].size);
							instr.operands[1].size = instr.operands[0].size;
						}
						else
						{
							op_code = 0x89;
							
							u8 reg_op = 0;
							u8 reg_mem = 0;
							u8 mode = 0;
							if((instr.operands[0].type == reg) && (instr.operands[1].type == reg))
							{							
								reg_op = (u8)(instr.operands[1].reg_address & 0b0111);
								reg_mem = (u8)(instr.operands[0].reg_address & 0b0111);
								mode = 0b11;
								
							}
							else if((instr.operands[0].type == u64_type) || (instr.operands[1].type == u64_type))
							{
								u32 var = 0;
								u32 reg = 1;
								if(instr.operands[1].type == u64_type)
								{
									op_code = 0x8b;
									reg = 0;
									var = 1;
								}
								
								reg_op = (u8)(instr.operands[reg].reg_address & 0b0111);
								reg_mem = 0b100;
								mode = 0b01;
								useSIB = TRUE;
								SIB = 0x24;
								useDisplacement = TRUE;
								Displacement = instr.operands[var].stack_offset;
								DisplacementSize = size_8;
							}
							
							modrm = (u8)((mode << 6) | (reg_op << 3) | reg_mem);
							useModrm = TRUE;
						}
						
					}break;
				}
				
				u8 rex = 0;
				if((instr.operands[0].size == size_64) || (instr.operands[1].size == size_64))
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
				
				if(useSIB == TRUE)
				{
					buffer_append_u8(&byte_code, SIB);
				}
				
				if(useDisplacement == TRUE)
				{
					if(DisplacementSize == size_8)
					{
						buffer_append_u8(&byte_code, (u8)Displacement);
					}
					else if(DisplacementSize == size_32)
					{
						buffer_append_u32(&byte_code, (u32)Displacement);
					}
				}
				
				if(instr.operands[0].type == import_function)
				{
					instr.operands[1] = instr.operands[0];
				}
				
				if((instr.operands[1].type == imm) || 
					 (instr.operands[1].type == string) || (instr.operands[1].type == import_function) || 
					 (instr.operands[1].type == label))
				{
					if((instr.operands[1].type == string) || (instr.operands[1].type == import_function) || 
						 (create_stack_patch == TRUE) || 
						 (instr.operands[1].type == label))
					{
						Patch *new_patch = (Patch *)(buffer_allocate(&buffer_patches, sizeof(Patch)));
						new_patch->location = byte_code.end;
						new_patch->variable_entry = instr.operands[1].variable_entry;
						patches.count++;
						
						create_stack_patch = FALSE;
					}
					
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
	
	s32 code_section_size = (s32)AlignSize((u32)(byte_code.end - byte_code.memory), PAGE);
	
	for(u32 i = 0; i < patches.count; i++)
	{
		Patch *current_patch = &patches.start[i];
		list_entry *var = current_patch->variable_entry;
		
		if(var == stack_entry)
		{
			*current_patch->location = (u8)stack_entry->imm_value;
		}
		else if(var->type == label)
		{
			s32 rip_relative = var->bytecode_offset - (s32)((current_patch->location + var->size) - byte_code.memory);
			
			*((s32 *)current_patch->location) = rip_relative;
		}
		else
		{
			s32 rip_relative = (code_section_size - (s32)((current_patch->location + var->size) - byte_code.memory)) + var->resource_offset;
			
			*((s32 *)current_patch->location) = rip_relative;
		}
		
	}
	
	header[0].bytes = byte_code.memory;
	header[0].len = (u64)(byte_code.end - byte_code.memory);
	header[1].bytes = resource.memory;
	header[1].len = (u64)(resource.end - resource.memory);
	
	clear_buffer(&buffer_patches);
	Memory->end = buffer_patches.memory;
	
	if(Reserved_Strings.temp_entry_start < Reserved_Strings.reserved.end)
	{
		DeallocateOffEnd(&Reserved_Strings.reserved, Reserved_Strings.temp_entry_start);
		Reserved_Strings.count--;
	}
}
