#include <windows.h>

#include "assembler.cpp"

global u32 PAGE;

#define DATA_DIR_COUNT 16

#define EXPORT        0
#define IMPORT        1
#define RESOURCE      2
#define EXCEPTION     3
#define CERTIFICATE   4
#define BASE_RELOC    5
#define DEBUG         6
#define ARCHITECTURE  7
#define GLOBAL_PTR    8
#define TLS           9
#define LOAD_CONFIG  10
#define BOUND        11
#define IAT          12
#define DELAY_IMPORT 13
#define CLR_RUNTIME  14
#define RESERVED     15

struct Base_Reloc_Entry
{
	u16 offset : 12;
	u16 type : 4;
};

#pragma pack(push, 1)
struct import_directory_table
{
	u32 ILT_RVA;
	u32 timeStamp;
	u32 forwarderChain;
	u32 nameRVA;
	u32 IAT_RVA;
};
#pragma pack(pop)

struct extracted_ILT
{
	u16 ordinal;
	u16 *hint;
	String functionName;
};

struct ILT_entry
{
	u64 *data;
	extracted_ILT *entry;
	u32 count;
};

struct IDT_entry
{
	String name;
	ILT_entry ILT;
};

struct extracted_IDT
{
	import_directory_table *IDT;
	IDT_entry *entries;
	u32 IDTCount;
};

#pragma pack(push, 1)
struct data_directory
{ 
	u32 VirtualAddress;
	u32 Size;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct dos_header
{
	char signature[2];
	u16 lastsize;
	u16 nblocks;
	u16 nreloc;
	u16 hdrsize;
	u16 minalloc;
	u16 maxalloc;
	u16 ss;
	u16 sp;
	u16 checksum;
	u16 ip;
	u16 cs;
	u16 relocpos;
	u16 noverlay;
	u16 reserved1[4];
	u16 oem_id;
	u16 oem_info;
	u16 reserved2[10];
	u32 e_lfanew;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct coff_header
{
	u8 PESignature[4];
	u16 machine;
	u16 numberOfSections;
	u32 timeDateStamp;
	u32 pointerToSymbolTable;
	u32 numberOfSymbols;
	u16 sizeOfOptionalHeader;
	u16 characteristics;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct pe_opt_header
{
	u16 Format;
	u8 MajorLinkerVersion; 
	u8 MinorLinkerVersion;
	u32 SizeOfCode;
	u32 SizeOfInitializedData;
	u32 SizeOfUninitializedData;
	u32 AddressOfEntryPoint;
	u32 BaseOfCode;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct coff_extension
{
	u64 ImageBase;
	u32 SectionAlignment;
	u32 FileAlignment;
	u16 MajorOSVersion;
	u16 MinorOSVersion;
	u16 MajorImageVersion;
	u16 MinorImageVersion;
	u16 MajorSubsystemVersion;
	u16 MinorSubsystemVersion;
	u32 Win32VersionValue;
	u32 SizeOfImage;
	u32 SizeOfHeaders;
	u32 Checksum;
	u16 Subsystem;
	u16 DLLCharacteristics;
	u64 SizeOfStackReserve;
	u64 SizeOfStackCommit;
	u64 SizeOfHeapReserve;
	u64 SizeOfHeapCommit;
	u32 LoaderFlags;
	u32 NumberOfRvaAndSizes;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct image_section_header
{
	u8  Name[8];
	union {
		u32 PhysicalAddress;
		u32 VirtualSize;
	};
	u32 VirtualAddress;
	u32 SizeOfRawData;
	u32 PointerToRawData;
	u32 PointerToRelocations;
	u32 PointerToLinenumbers;
	u16 NumberOfRelocations;
	u16 NumberOfLinenumbers;
	u32 Characteristics;
};
#pragma pack(pop)

struct win64_file_header
{
	dos_header *DOSHeader;
	coff_header *COFFHeader;
	pe_opt_header *PEOptHeader;
	
	coff_extension *COFFExtension;
	data_directory *dataDirectory;
	image_section_header *SectionHeader;
};

#pragma pack(push, 1)
struct debug_directory
{
	u32 characteristics;
	u32 timeStamp;
	u16 majorVersion;
	u16 minorVersion;
	u32 type;
	u32 sizeOfData;
	u32 addressOfRawData;
	u32 pointerToRawData;
};
#pragma pack(pop)

int __stdcall
WinMainCRTStartup
(void)
{
	
	SYSTEM_INFO SysInfo = {};
	GetSystemInfo(&SysInfo);
	Assert(SysInfo.dwPageSize != 0);
	PAGE = SysInfo.dwPageSize;
	
	// TODO: GetCommandLine for the name of the file to assemble and name of file to output
	
	Buffer winData = win64_make_buffer(PAGE, PAGE_READWRITE);
	String outputName = create_string(&winData, "d:\\programming\\github\\assembler\\game\\build\\game.exe");
	// NOTE: This is going to get passed to Windows and needs to be null terminated.
	buffer_append_u8(&winData, 0);
	
	read_file_result file = Win64ReadEntireFile("d:\\programming\\github\\assembler\\game\\project\\code\\game.laugh");
	String src = {};
	src.chars = (u8 *)file.Contents;
	src.len = GetStringLength(src.chars);
	
	Buffer chunk_of_memory = win64_make_buffer(2*PAGE, PAGE_READWRITE);
	Buffer assembled = win64_make_buffer(PAGE, PAGE_READWRITE);
	assemble(&assembled, &chunk_of_memory, src, PAGE);
	U8_Array *assembled_header = (U8_Array *)(assembled.memory);
	
	Buffer program = win64_make_buffer(PAGE, PAGE_READWRITE);
	dos_header *dos = (dos_header *)(buffer_allocate(&program, sizeof(dos_header)));
	dos->signature[0] = 'M';
	dos->signature[1] = 'Z';
	dos->e_lfanew = sizeof(dos_header);
	
	coff_header *coff = (coff_header *)(buffer_allocate(&program, sizeof(coff_header)));
	coff->PESignature[0] = 'P';
	coff->PESignature[1] = 'E';
	coff->machine = 0x8664; // NOTE: AMD64
	coff->numberOfSections = (u16)((assembled_header[1].len > 0) ? 2 : 1);
	
	// NOTE: filetime is in 100 nanoseconds
	FILETIME filetime = {};
	GetSystemTimePreciseAsFileTime(&filetime);
	u64 time = ((u64)filetime.dwHighDateTime << 32) | ((u64)filetime.dwLowDateTime);
	time = time/(u64)10000000; // Convert to seconds
	coff->timeDateStamp = (u32)time; // Only preserve the low order bits per the docs
	coff->sizeOfOptionalHeader = sizeof(pe_opt_header) + sizeof(coff_extension) + (sizeof(data_directory) * DATA_DIR_COUNT);
	coff->characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DEBUG_STRIPPED;
	
	pe_opt_header *optionalHeader = (pe_opt_header *)(buffer_allocate(&program, sizeof(pe_opt_header)));
	optionalHeader->Format = 0x20b; // NOTE: To indicate a PE32+ format
	optionalHeader->SizeOfCode = (u32)(assembled_header[0].len);
	
	// NOTE: byte code is the first section and PAGE is the section alignment
	optionalHeader->AddressOfEntryPoint = 1 * PAGE; // NOTE: main starts at the top
	optionalHeader->BaseOfCode = 1 * PAGE;
	
	coff_extension *extension = (coff_extension *)(buffer_allocate(&program, sizeof(coff_extension)));
	extension->ImageBase = 0x00400000; // NOTE: docs say this is the default for an exe
	extension->SectionAlignment = PAGE;
	extension->FileAlignment = 512; // NOTE: docs say this is the default
	// NOTE: 5.2 is for Windows XP 64 bit
	extension->MajorOSVersion = 5;
	extension->MinorOSVersion = 2;
	extension->MajorSubsystemVersion = 5;
	extension->MinorSubsystemVersion = 2;
	
	u32 headerSize = sizeof(dos_header) + sizeof(coff_header) + coff->sizeOfOptionalHeader + (sizeof(image_section_header) * coff->numberOfSections);
	extension->SizeOfHeaders = AlignSize(headerSize, extension->FileAlignment);
	
	extension->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	extension->DLLCharacteristics = 
		IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA | 
		IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | 
		IMAGE_DLLCHARACTERISTICS_NX_COMPAT | 
		IMAGE_DLLCHARACTERISTICS_NO_ISOLATION | 
		IMAGE_DLLCHARACTERISTICS_NO_SEH | 
		IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
	extension->SizeOfStackReserve = 0x100000;
	extension->SizeOfStackCommit = 0x100000;
	extension->NumberOfRvaAndSizes = 16;
	
	data_directory *data_dirs = (data_directory *)buffer_allocate(&program, (sizeof(data_directory) * DATA_DIR_COUNT));
	unreferenced(data_dirs);
	
	image_section_header *CodeSectionHeader = (image_section_header *)(buffer_allocate(&program, sizeof(image_section_header)));
	CodeSectionHeader->Name[0] = '.';
	CodeSectionHeader->Name[1] = 't';
	CodeSectionHeader->Name[2] = 'e';
	CodeSectionHeader->Name[3] = 'x';
	CodeSectionHeader->Name[4] = 't';
	CodeSectionHeader->VirtualSize = optionalHeader->SizeOfCode;
	CodeSectionHeader->SizeOfRawData = AlignSize(optionalHeader->SizeOfCode, extension->FileAlignment);
	CodeSectionHeader->PointerToRawData = extension->SizeOfHeaders;
	CodeSectionHeader->Characteristics = 
		IMAGE_SCN_CNT_CODE |
		IMAGE_SCN_MEM_EXECUTE |
		IMAGE_SCN_MEM_READ;
	
	image_section_header *RDataSectionHeader = 0;
	if(assembled_header[1].len != 0)
	{
		RDataSectionHeader = (image_section_header *)(buffer_allocate(&program, sizeof(image_section_header)));
		RDataSectionHeader->Name[0] = '.';
		RDataSectionHeader->Name[1] = 'r';
		RDataSectionHeader->Name[2] = 'd';
		RDataSectionHeader->Name[3] = 'a';
		RDataSectionHeader->Name[4] = 't';
		RDataSectionHeader->Name[5] = 'a';
		RDataSectionHeader->VirtualSize = (u32)assembled_header[1].len;
		RDataSectionHeader->SizeOfRawData = AlignSize((u32)assembled_header[1].len, extension->FileAlignment);
		RDataSectionHeader->PointerToRawData = CodeSectionHeader->PointerToRawData + CodeSectionHeader->SizeOfRawData;
		RDataSectionHeader->Characteristics = 
			IMAGE_SCN_CNT_INITIALIZED_DATA |
			IMAGE_SCN_MEM_READ;
	}
	
	u32 headers_size = (u32)(program.end - program.memory);
	u32 needed_size_adjustment = extension->SizeOfHeaders - headers_size;
	if(needed_size_adjustment > 0)
	{
		buffer_allocate(&program, needed_size_adjustment);
	}
	
	u32 virtual_aligned_header = AlignSize(extension->SizeOfHeaders, extension->SectionAlignment);
	CodeSectionHeader->VirtualAddress = virtual_aligned_header;
	
	extension->SizeOfImage = virtual_aligned_header;
	u32 code_virtual_size = AlignSize(CodeSectionHeader->SizeOfRawData, extension->SectionAlignment);
	extension->SizeOfImage += code_virtual_size;
	if(RDataSectionHeader != 0)
	{
		extension->SizeOfImage += AlignSize(RDataSectionHeader->SizeOfRawData, extension->SectionAlignment);
		
		RDataSectionHeader->VirtualAddress = CodeSectionHeader->VirtualAddress + code_virtual_size;
	}
	
	u8 *TextSection = buffer_allocate(&program, CodeSectionHeader->SizeOfRawData);
	
	for(u32 i = 0; i < assembled_header[0].len; i++)
	{
		TextSection[i] = assembled_header[0].bytes[i];
	}
	
	if(RDataSectionHeader != 0)
	{
		u8 *RDataSection = buffer_allocate(&program, RDataSectionHeader->SizeOfRawData);
		
		for(u32 i = 0; i < assembled_header[1].len; i++)
		{
			RDataSection[i] = assembled_header[1].bytes[i];
		}
	}
	
	u32 programSize = (u32)(program.end - program.memory);
	b32 writeSucceded = Win64WriteEntireFile((char *)outputName.chars, programSize, (void *)program.memory);
	unreferenced(writeSucceded);
	
	return(0);
}