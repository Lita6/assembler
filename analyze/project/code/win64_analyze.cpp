#include <windows.h>

#include "win64_analyze.h"

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

image_section_header *
GetSection
(image_section_header *Sections, u32 SectionCount, u32 SectionAlignment, u32 VirtualAddress)
{
	image_section_header *result = 0;
	for(u32 i = 0; i < SectionCount; i++)
	{
		u32 MinAddress = Sections[i].VirtualAddress;
		u32 MaxAddress = Sections[i].VirtualAddress + SectionAlignment;
		
		if((VirtualAddress >= MinAddress) && (VirtualAddress < MaxAddress))
		{
			result = &Sections[i];
			break;
		}
		
	}
	return(result);
}

u32
GetFileAddress
(image_section_header *Sections, u32 SectionCount, u32 SectionAlignment, u32 DataRVA)
{
	u32 result = 0;
	
	image_section_header *Section = GetSection(Sections, SectionCount, SectionAlignment, DataRVA);
	if(Section != 0)
	{
		u32 diff = DataRVA - Section->VirtualAddress;
		result = diff + Section->PointerToRawData;
	}
	
	return(result);
}

int __stdcall
WinMainCRTStartup
(void)
{
	
	SYSTEM_INFO SysInfo = {};
	GetSystemInfo(&SysInfo);
	Assert(SysInfo.dwPageSize != 0);
	PAGE = SysInfo.dwPageSize;
	
	Buffer Strings = win64_make_buffer(PAGE, PAGE_READWRITE);
	Buffer Buffer_IDT  = win64_make_buffer(PAGE, PAGE_READWRITE);
	Buffer Buffer_ILT  = win64_make_buffer(PAGE, PAGE_READWRITE);
	
	String Hexadecimals = create_string(&Strings, "0123456789ABCDEF");
	
	read_file_result Executable = Win64ReadEntireFile("D:\\Programming\\GitHub\\assembler\\HMH\\build\\win64_handmade.exe");
	DWORD OldProtect = 0;
	s32 ChangedProtection = VirtualProtect(Executable.Contents, Executable.ContentsSize, PAGE_READONLY, &OldProtect);
	if(ChangedProtection == 0)
	{
		u32 ErrorCode = GetLastError();
		Assert(!"Failed to change executable protection.");
		(void)ErrorCode;
	}
	
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
	
	data_directory *Export_Data = &header.dataDirectory[EXPORT];
	(void)Export_Data;
	data_directory *Import_Data = &header.dataDirectory[IMPORT];
	(void)Import_Data;
	data_directory *Resource_Data = &header.dataDirectory[RESOURCE];
	(void)Resource_Data;
	data_directory *Exception_Data = &header.dataDirectory[EXCEPTION];
	(void)Exception_Data;
	data_directory *Certificate_Data = &header.dataDirectory[CERTIFICATE];
	(void)Certificate_Data;
	data_directory *Base_Reloc_Data = &header.dataDirectory[BASE_RELOC];
	(void)Base_Reloc_Data;
	data_directory *Debug_Data = &header.dataDirectory[DEBUG];
	(void)Debug_Data;
	data_directory *Architecture_Data = &header.dataDirectory[ARCHITECTURE];
	(void)Architecture_Data;
	data_directory *Global_Ptr_Data = &header.dataDirectory[GLOBAL_PTR];
	(void)Global_Ptr_Data;
	data_directory *TLS_Data = &header.dataDirectory[TLS];
	(void)TLS_Data;
	data_directory *Load_Config_Data = &header.dataDirectory[LOAD_CONFIG];
	(void)Load_Config_Data;
	data_directory *Bound_Data = &header.dataDirectory[BOUND];
	(void)Bound_Data;
	data_directory *IAT_Data = &header.dataDirectory[IAT];
	(void)IAT_Data;
	data_directory *Delay_Import_Data = &header.dataDirectory[DELAY_IMPORT];
	(void)Delay_Import_Data;
	data_directory *CLR_Runtime_Data = &header.dataDirectory[CLR_RUNTIME];
	(void)CLR_Runtime_Data;
	data_directory *Reserved_Data = &header.dataDirectory[RESERVED];
	(void)Reserved_Data;
	
	header.SectionHeader = (image_section_header *)((u8 *)header.PEOptHeader + header.COFFHeader->sizeOfOptionalHeader);
	
	u32 debugAddress = GetFileAddress(header.SectionHeader, header.COFFHeader->numberOfSections, header.COFFExtension->SectionAlignment, Debug_Data->VirtualAddress);
	debug_directory *debug = 0;
	u32 debugEntries = 0;
	if(debugAddress != 0)
	{	
		debug = (debug_directory *)((u8 *)Executable.Contents + debugAddress);
		debugEntries = Debug_Data->Size/sizeof(debug_directory);
	}
	
	u32 importAddress = GetFileAddress(header.SectionHeader, header.COFFHeader->numberOfSections, header.COFFExtension->SectionAlignment, Import_Data->VirtualAddress);
	extracted_IDT ImportTable = {};
	if(importAddress != 0)
	{
		ImportTable.IDT = (import_directory_table *)((u8 *)Executable.Contents + importAddress);
		ImportTable.entries = (IDT_entry *)buffer_allocate(&Buffer_IDT, sizeof(IDT_entry));
		
		import_directory_table *current = ImportTable.IDT;
		while(TRUE)
		{
			if(IsMemZero((u8 *)current, sizeof(import_directory_table)))
			{
				Buffer_IDT.end -= sizeof(IDT_entry); // NOTE: Deallocate unused memory in buffer.
				break;
			}
			
			u32 nameAddress = GetFileAddress(header.SectionHeader, header.COFFHeader->numberOfSections, header.COFFExtension->SectionAlignment, current->nameRVA);
			ImportTable.entries[ImportTable.IDTCount].name.chars = (u8 *)Executable.Contents + nameAddress;
			ImportTable.entries[ImportTable.IDTCount].name.len = GetStringLength(ImportTable.entries[ImportTable.IDTCount].name.chars);
			u32 ILTAddress = GetFileAddress(header.SectionHeader, header.COFFHeader->numberOfSections, header.COFFExtension->SectionAlignment, current->ILT_RVA);
			ImportTable.entries[ImportTable.IDTCount].ILT.data = (u64 *)((u8 *)Executable.Contents + ILTAddress);
			
			ILT_entry *iltEntry = &ImportTable.entries[ImportTable.IDTCount].ILT;
			u64 *data = ImportTable.entries[ImportTable.IDTCount].ILT.data;
			iltEntry->entry = (extracted_ILT *)(buffer_allocate(&Buffer_ILT, sizeof(extracted_ILT)));
			extracted_ILT *currentILT = iltEntry->entry;
			while(TRUE)
			{
				
				if(*data == 0)
				{
					// NOTE: Deallocate unused memory in buffer.
					Buffer_ILT.end -= sizeof(extracted_ILT);
					break;
				}
				
				u64 bitmask = (u64)1<<63;
				b32 IsOrdinal = ((*data) & bitmask) > 0;
				if(IsOrdinal == FALSE)
				{
					
					u32 hintAddress = GetFileAddress(header.SectionHeader, header.COFFHeader->numberOfSections, header.COFFExtension->SectionAlignment, (u32)(*data));
					currentILT->hint = (u16 *)((u8 *)Executable.Contents + hintAddress);
					currentILT->functionName.chars = (u8 *)(currentILT->hint + 1);
					currentILT->functionName.len = GetStringLength(currentILT->functionName.chars);
					
				}
				else
				{
					
					currentILT->ordinal = (u16)(*data);
				}
				
				iltEntry->count++;
				data++;
				currentILT = (extracted_ILT *)buffer_allocate(&Buffer_ILT, sizeof(extracted_ILT));
			}
			
			current++;
			ImportTable.IDTCount++;
			buffer_allocate(&Buffer_IDT, sizeof(IDT_entry));
			
		}
	}
	
	return(0);
}