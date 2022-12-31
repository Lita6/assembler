#include <windows.h>

#include "assembler.cpp"

global u32 PAGE;

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
	} Misc;
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
	
	// TODO: GetCommandLine for the name of the file to assemble
	
	read_file_result file = Win64ReadEntireFile("d:\\programming\\github\\assembler\\game\\game.laf");
	String src = {};
	src.chars = (u8 *)file.Contents;
	src.len = GetStringLength(src.chars);
	
	Buffer reserved = win64_make_buffer(PAGE, PAGE_READWRITE);
	Buffer strings = win64_make_buffer(PAGE, PAGE_READWRITE);
	init(&reserved, &strings);
	
	Buffer byte_code = win64_make_buffer(PAGE, PAGE_EXECUTE_READWRITE);
	assemble(&byte_code, src);
	
	Buffer program = win64_make_buffer(PAGE, PAGE_READWRITE);
	dos_header *dos = (dos_header *)program.memory;
	dos->signature[0] = 'M';
	dos->signature[1] = 'Z';
	dos->e_lfanew = sizeof(dos_header);
	
	coff_header *coff = (coff_header *)(program.memory + dos->e_lfanew);
	coff->PESignature[0] = 'P';
	coff->PESignature[1] = 'E';
	coff->machine = 0x8664;
	coff->numberOfSections = 1;
	
	// NOTE: filetime is in 100 nanoseconds
	FILETIME filetime = {};
	GetSystemTimePreciseAsFileTime(&filetime);
	u64 time = ((u64)filetime.dwHighDateTime << 32) | ((u64)filetime.dwLowDateTime);
	time = time/(u64)10000000; // Convert to seconds
	coff->timeDateStamp = (u32)time; // Only preserve the low order bits per the docs
	coff->sizeOfOptionalHeader = sizeof(pe_opt_header) + sizeof(coff_extension) + (sizeof(data_directory) * 16);
	coff->characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DEBUG_STRIPPED;
	
	pe_opt_header *optionalHeader = (pe_opt_header *)((u8 *)coff + sizeof(coff_header));
	optionalHeader->Format = 0x20b; // NOTE: To indicate a PE32+ format
	optionalHeader->SizeOfCode = (u32)(byte_code.end - byte_code.memory);
	
	// NOTE: byte code is the first section and PAGE is the section alignment
	optionalHeader->AddressOfEntryPoint = 1 * PAGE; // NOTE: main starts at the top
	optionalHeader->BaseOfCode = 1 * PAGE;
	
	coff_extension *extension = (coff_extension *)((u8 *)optionalHeader + sizeof(pe_opt_header));
	extension->ImageBase = 0x00400000; // NOTE: docs say this is the default for an exe
	extension->SectionAlignment = PAGE;
	extension->FileAlignment = 512; // NOTE: docs say this is the default
	// NOTE: 5.2 is for Windows XP 64 bit
	extension->MajorOSVersion = 5;
	extension->MinorOSVersion = 2;
	extension->MajorSubsystemVersion = 5;
	extension->MinorSubsystemVersion = 2;
	extension->SizeOfImage = extension->SectionAlignment * (coff->numberOfSections + 1);
	
	u32 headerSize = sizeof(dos_header) + sizeof(coff_header) + coff->sizeOfOptionalHeader + (sizeof(image_section_header) * coff->numberOfSections);
	
	u32 mod = headerSize % extension->FileAlignment;
	if(mod != 0)
	{
		headerSize += extension->FileAlignment - mod;
	}
	extension->SizeOfHeaders = headerSize;
	
	extension->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	extension->DLLCharacteristics = 
		IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA | 
		IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | 
		IMAGE_DLLCHARACTERISTICS_NX_COMPAT | 
		IMAGE_DLLCHARACTERISTICS_NO_ISOLATION | 
		IMAGE_DLLCHARACTERISTICS_NO_SEH | 
		IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
	
	// TODO: Figure out about stacks and heaps
	
	extension->NumberOfRvaAndSizes = 16;
	
	return(0);
}