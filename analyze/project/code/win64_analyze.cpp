#include <windows.h>

#include "win64_analyze.h"

global u32 PAGE;

struct ILT_Entry_64bit
{
	union{
		u32 ordinal : 16;
		u32 hint_name : 32;
	};
	
	u32 ordinal_name_flag : 1;
};

struct Base_Reloc_Entry
{
	u16 offset : 12;
	u16 type : 4;
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
	u16 PESignature;
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
	
	u32 BaseOfData; // If the file is 32 bit, then this gets used and takes up space.
	
	coff_extension *COFFExtension;
	data_directory *dataDirectory;
	image_section_header *SectionHeader;
};

int __stdcall
WinMainCRTStartup
(void)
{
	
	SYSTEM_INFO SysInfo = {};
	GetSystemInfo(&SysInfo);
	Assert(SysInfo.dwPageSize != 0);
	PAGE = SysInfo.dwPageSize;
	
	Buffer Strings = win64_make_buffer(PAGE, PAGE_READWRITE);
	
	String Hexadecimals = create_string(&Strings, "0123456789ABCDEF");
	
	read_file_result Executable = Win64ReadEntireFile("D:\\Programming\\GitHub\\assembler\\HMH\\build\\win64_handmade.exe");
	
	win64_file_header header = {};
	header.DOSHeader = (dos_header *)Executable.Contents;
	
	u32 PE00 = 4;
	header.COFFHeader = (coff_header *)((u8 *)Executable.Contents + header.DOSHeader->e_lfanew + PE00);
	
	header.PEOptHeader = (pe_opt_header *)((u8 *)header.COFFHeader + sizeof(coff_header));
	
	u8 *EndPEOptHeader = (u8 *)header.PEOptHeader + sizeof(pe_opt_header);
	if(header.PEOptHeader->PESignature == 0x10b)
	{
		Assert(!"32 bit version of PE Optional Header required.");
		//header.BaseOfData = *(u32 *)EndPEOptHeader;
		//EndPEOptHeader += sizeof(u32);
	}
	
	header.COFFExtension = (coff_extension *)EndPEOptHeader;
	header.dataDirectory = (data_directory *)((u8 *)header.COFFExtension + sizeof(coff_extension));
	
	// TODO: Section header comes right after PE Optional Header and the docs recommends using the sizeOfOptionalHeader in the COFFHeader structure to find it.
	
	return(0);
}