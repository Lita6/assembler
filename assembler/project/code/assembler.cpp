/* TODO: There's a few things to do to get my program somewhere that can call
*        a windows function
*
	*    HMODULE kernell32 = LoadLibraryA("KERNELL32.dll");
	*    fn func = (fn)GetProcAddress(kernell32, "OutputDebugStringA");
	*    func("This is the first thing we have printed.\n");
	*
*    rsp - STACK_ADJUST
*    kernell32_name &-> rcx
*    call LoadLibraryA
*    kernell32 <- rax // so kernell32 goes on the stack
*    string output_name "OutputDebugStringA\0"
*    rcx <- kernell32
*    output_name &-> rdx
*    call GetProcAddress
*    winDebugString <- rax
*    string winString "Hello, World!\0"
*    winString &-> rcx
*    call winDebugString
*    eax <- 0
*    rsp + STACK_ADJUST
*    ret
*
*    call a function pointer based on rip
*    - window's loader is going to put the function address in my program
*
*    - implement variables
*      - variable to keep track of stack adjustment amount
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
	string_word,
	reg,
	imm,
	string,
	import_function,
};

struct list_entry
{
	list_entry_type type;
	String name;
	u8 size;
	u8 opcode_extension;
	u8 reg_address;
	u64 imm_value;
	s32 resource_offset;
	list_entry *variable_entry;
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
	Buffer strings;
};

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
	u8 kernell32_name[14];
	u16 loadlibrary_hint;
	u8 loadlibrary_name[14];
	u16 getproc_hint;
	u8 getproc_name[16];
};
#pragma pack(pop)

void
assemble
(Buffer *program, Buffer *Memory, String src, u32 PAGE)
{
	
	U8_Array *header = (U8_Array *)(buffer_allocate(program, (2 * sizeof(U8_Array))));
	Buffer byte_code = create_buffer(program, 64);
	Buffer resource = create_buffer(program, 200);
	Import_Data_Table *import_table = (Import_Data_Table *)(buffer_allocate(&resource, sizeof(Import_Data_Table)));
	
	u32 loadlibrary_offset = (u32)((u8 *)(&import_table->load_lib_address) - resource.memory);
	
	import_table->ILT_RVA = (u32)((u8 *)(&import_table->load_lib_lookup) - resource.memory) + PAGE*2;
	u32 kernell32_name_offset = (u32)(import_table->kernell32_name - resource.memory);
	import_table->nameRVA = kernell32_name_offset + PAGE*2;
	import_table->IAT_RVA = loadlibrary_offset + PAGE*2;
	
	u32 loadlibrary_RVA = (u32)((u8 *)(&import_table->loadlibrary_hint) - resource.memory) + PAGE*2;
	import_table->load_lib_address = import_table->load_lib_lookup = loadlibrary_RVA;
	
	u32 getproc_RVA = (u32)((u8 *)(&import_table->getproc_hint) - resource.memory) + PAGE*2;
	import_table->get_proc_address = import_table->get_proc_lookup = getproc_RVA;
	
	StuffStringIntoArray(import_table->kernell32_name, "KERNELL32.dll", (u32)14);
	StuffStringIntoArray(import_table->loadlibrary_name, "LoadLibraryA", (u32)14);
	StuffStringIntoArray(import_table->getproc_name, "GetProcAddress", (u32)16);
	
	b8 *IsInitialized = (b8 *)Memory->memory;
	if(*IsInitialized == FALSE)
	{
		// NOTE: Need to reserve space for IsInitialized
		buffer_allocate(Memory, size_8);
		
		Reserved_Strings.strings = create_buffer(Memory, 1024);
		Reserved_Strings.reserved = create_buffer(Memory, 1024*3);
		ReserveStrings();
		
		add_to_list(&Reserved_Strings, "kernell32_name", string, 0, 0, 0, (s32)kernell32_name_offset, 0);
		add_to_list(&Reserved_Strings, "LoadLibraryA", import_function, 0, 0, 0, (s32)loadlibrary_offset, 0);
		add_to_list(&Reserved_Strings, "GetProcAddress", import_function, 0, 0, 0, (s32)((u8 *)(&import_table->get_proc_address) - resource.memory), 0);
		
		*IsInitialized = TRUE;
	}
	
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
	for(u64 i = 0; i <= EndOfFile; i++)
	{
		if(processString == FALSE)
		{
			
			if(IsWhiteSpace(src.chars[i]) == TRUE)
			{
				CompleteToken = (token.chars == 0) ? FALSE : TRUE;
				
				if((src.chars[i] == '\r') || (src.chars[i] == '\n'))
				{
					if((newEntry != 0) && (StringChars != 0))
					{
						newEntry->resource_offset = (s32)(StringChars - resource.memory);
					}
					
					newEntry = 0;
					StringChars = 0;
					StringLen = 0;
					
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
						
						if((entry->type == reg) || (entry->type == string))
						{
							instr.operands[CurrentOperand] = *entry;
							instr.operands[CurrentOperand].variable_entry = entry;
							CurrentOperand++;
							if((CurrentOperand == 2) && (instr.operation.type != none))
							{
								InstructionComplete = TRUE;
							}
							
						}
						else if(entry->type == string_word)
						{
							processVariableName = TRUE;
							newEntry = (list_entry *)buffer_allocate(&Reserved_Strings.reserved, sizeof(list_entry));
							Reserved_Strings.count++;
							newEntry->type = string;
							newEntry->size = size_32;
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
					
					case lea_right:
					{
						swap_operands(&instr);
					}; // NOTE: Fall through to lea_left.
					case lea_left:
					{
						// 48 8d 0d 59 00 00 00
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
				
				if((instr.operands[1].type == imm) || (instr.operands[1].type == string))
				{
					if(instr.operands[1].type == string)
					{
						Patch *new_patch = (Patch *)(buffer_allocate(&buffer_patches, sizeof(Patch)));
						new_patch->location = byte_code.end;
						new_patch->variable_entry = instr.operands[1].variable_entry;
						patches.count++;
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
		
		// NOTE: I cheated for now cause I know the rip-relative string patches are all 32 bit and are the only patches I have right now
		s32 rip_relative = (code_section_size - (s32)((current_patch->location + var->size) - byte_code.memory)) + var->resource_offset;
		
		*((s32 *)current_patch->location) = rip_relative;
		
	}
	
	header[0].bytes = byte_code.memory;
	header[0].len = (u64)(byte_code.end - byte_code.memory);
	header[1].bytes = resource.memory;
	header[1].len = (u64)(resource.end - resource.memory);
	
	clear_buffer(&buffer_patches);
	Memory->end = buffer_patches.memory;
}
