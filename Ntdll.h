#pragma once
#include "pin.H"

/* NTDLL shit*/
namespace ntdll {
#define RTL_MAX_DRIVE_LETTERS 32

	typedef unsigned long ULONG;
#if defined(_WIN64)
	typedef unsigned __int64 ULONG_PTR;
#else
	typedef unsigned long ULONG_PTR;
#endif
	typedef ULONG_PTR SIZE_T;
	typedef SIZE_T* PSIZE_T;
	typedef short SHORT;
	typedef unsigned short USHORT;
	typedef unsigned short WORD;
	typedef unsigned long DWORD;

	typedef long LONG;
	typedef unsigned long ULONG;
#if !defined(_M_IX86)
	typedef __int64 LONGLONG;
	typedef unsigned __int64 ULONGLONG;
	typedef unsigned __int64 DWORD64, * PDWORD64;
#else
	typedef double LONGLONG;
	typedef double ULONGLONG;
#endif


	typedef char CHAR;
	typedef unsigned char BYTE;
	typedef CHAR* PCHAR;
	typedef unsigned char UCHAR;
	typedef wchar_t  WCHAR;
	typedef WCHAR* PWCHAR;
	typedef const WCHAR* PCWSTR;
	typedef const CHAR* PCSTR;

	typedef VOID* PVOID;
	typedef void* LPVOID;

	typedef PVOID HANDLE;
	typedef HANDLE* PHANDLE;
	typedef HANDLE HMODULE;

	typedef long NTSTATUS;

	typedef ULONG  ACCESS_MASK;

	typedef struct _UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PVOID Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef struct _ANSI_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PCHAR Buffer;
	} ANSI_STRING, * PANSI_STRING, STRING, * PSTRING, OEM_STRING, * POEM_STRING;


	typedef struct _OBJECT_ATTRIBUTES {
		ULONG           Length;
		HANDLE          RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG           Attributes;
		PVOID           SecurityDescriptor;
		PVOID           SecurityQualityOfService;
	} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

	typedef struct _IO_STATUS_BLOCK {
		union {
			NTSTATUS Status;
			PVOID    Pointer;
		};
		ULONG_PTR Information;
	} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

	typedef union _LARGE_INTEGER {
		struct {
			DWORD LowPart;
			LONG  HighPart;
		} DUMMYSTRUCTNAME;
		struct {
			DWORD LowPart;
			LONG  HighPart;
		} u;
		LONGLONG QuadPart;
	} LARGE_INTEGER, *PLARGE_INTEGER;

	typedef struct _CLIENT_ID {
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;

	typedef struct _CURDIR {
		UNICODE_STRING DosPath;
		HANDLE Handle;
	} CURDIR, * PCURDIR;

	typedef struct _RTL_DRIVE_LETTER_CURDIR {
		USHORT Flags;
		USHORT Length;
		ULONG TimeStamp;
		STRING DosPath;
	} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		ULONG MaximumLength;
		ULONG Length;

		ULONG Flags;
		ULONG DebugFlags;

		HANDLE ConsoleHandle;
		ULONG ConsoleFlags;
		HANDLE StandardInput;
		HANDLE StandardOutput;
		HANDLE StandardError;

		CURDIR CurrentDirectory;
		UNICODE_STRING DllPath;
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
		PVOID Environment;

		ULONG StartingX;
		ULONG StartingY;
		ULONG CountX;
		ULONG CountY;
		ULONG CountCharsX;
		ULONG CountCharsY;
		ULONG FillAttribute;

		ULONG WindowFlags;
		ULONG ShowWindowFlags;
		UNICODE_STRING WindowTitle;
		UNICODE_STRING DesktopInfo;
		UNICODE_STRING ShellInfo;
		UNICODE_STRING RuntimeData;
		RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

		ULONG EnvironmentSize;
		ULONG EnvironmentVersion;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	/*
	 * Function prototype 
	 */
	typedef void(__stdcall* LdrLoadDll)(
			PWCHAR PathToFile,
			ULONG Flags,
			PUNICODE_STRING ModuleFileName,
			HMODULE* ModuleHandle
	);

	typedef void(__stdcall* LdrGetProcedureAddress)(
			HMODULE ModuleHandle,
			PANSI_STRING FunctionName,
			WORD Ordinal,
			PVOID* FunctionAddress
	);

	typedef void(__stdcall* RtlInitUnicodeString)(
			PUNICODE_STRING DestinationString,
			PCWSTR SourceString
	);

	typedef void(__stdcall* RtlInitAnsiString)(
			PANSI_STRING DestinationString,
			PCSTR SourceString
	);

	typedef DWORD(__stdcall* LPTHREAD_START_ROUTINE) (
			LPVOID lpThreadParameter
	);



	/*
	* Parsing PE file
	*/
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#define	IMAGE_DIRECTORY_ENTRY_EXPORT		0
#define	IMAGE_DIRECTORY_ENTRY_IMPORT		1
#define	IMAGE_DIRECTORY_ENTRY_RESOURCE		2
#define	IMAGE_DIRECTORY_ENTRY_EXCEPTION		3
#define	IMAGE_DIRECTORY_ENTRY_SECURITY		4
#define	IMAGE_DIRECTORY_ENTRY_BASERELOC		5
#define	IMAGE_DIRECTORY_ENTRY_DEBUG		6
#define	IMAGE_DIRECTORY_ENTRY_COPYRIGHT		7
#define	IMAGE_DIRECTORY_ENTRY_GLOBALPTR		8   /* (MIPS GP) */
#define	IMAGE_DIRECTORY_ENTRY_TLS		9
#define	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG	10
#define	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT	11
#define	IMAGE_DIRECTORY_ENTRY_IAT		12  /* Import Address Table */
#define	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT	13
#define	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	14

	/* Subsystem Values */

#define	IMAGE_SUBSYSTEM_UNKNOWN			0
#define	IMAGE_SUBSYSTEM_NATIVE			1
#define	IMAGE_SUBSYSTEM_WINDOWS_GUI		2	/* Windows GUI subsystem */
#define	IMAGE_SUBSYSTEM_WINDOWS_CUI		3	/* Windows character subsystem */
#define	IMAGE_SUBSYSTEM_OS2_CUI			5
#define	IMAGE_SUBSYSTEM_POSIX_CUI		7
#define	IMAGE_SUBSYSTEM_NATIVE_WINDOWS		8	/* native Win9x driver */
#define	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI		9	/* Windows CE subsystem */
#define	IMAGE_SUBSYSTEM_EFI_APPLICATION		10
#define	IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER	11
#define	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER	12
#define	IMAGE_SUBSYSTEM_EFI_ROM			13
#define	IMAGE_SUBSYSTEM_XBOX			14
#define	IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION	16

/* DLL Characteristics */
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       0x0020
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          0x0040
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       0x0080
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT             0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                0x0400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND               0x0800
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER          0x1000
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            0x2000
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF              0x4000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

	/* Possible Magic values */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

#ifdef _WIN64
#define IMAGE_NT_OPTIONAL_HDR_MAGIC     IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
#define IMAGE_NT_OPTIONAL_HDR_MAGIC     IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif

/* These are indexes into the DataDirectory array */
#define IMAGE_FILE_EXPORT_DIRECTORY		0
#define IMAGE_FILE_IMPORT_DIRECTORY		1
#define IMAGE_FILE_RESOURCE_DIRECTORY		2
#define IMAGE_FILE_EXCEPTION_DIRECTORY		3
#define IMAGE_FILE_SECURITY_DIRECTORY		4
#define IMAGE_FILE_BASE_RELOCATION_TABLE	5
#define IMAGE_FILE_DEBUG_DIRECTORY		6
#define IMAGE_FILE_DESCRIPTION_STRING		7
#define IMAGE_FILE_MACHINE_VALUE		8  /* Mips */
#define IMAGE_FILE_THREAD_LOCAL_STORAGE		9
#define IMAGE_FILE_CALLBACK_DIRECTORY		10
	typedef struct _IMAGE_DOS_HEADER
	{
		WORD e_magic;
		WORD e_cblp;
		WORD e_cp;
		WORD e_crlc;
		WORD e_cparhdr;
		WORD e_minalloc;
		WORD e_maxalloc;
		WORD e_ss;
		WORD e_sp;
		WORD e_csum;
		WORD e_ip;
		WORD e_cs;
		WORD e_lfarlc;
		WORD e_ovno;
		WORD e_res[4];
		WORD e_oemid;
		WORD e_oeminfo;
		WORD e_res2[10];
		LONG e_lfanew;
	} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

	typedef struct _IMAGE_FILE_HEADER
	{
		WORD Machine;
		WORD NumberOfSections;
		ULONG TimeDateStamp;
		ULONG PointerToSymbolTable;
		ULONG NumberOfSymbols;
		WORD SizeOfOptionalHeader;
		WORD Characteristics;
	} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

	typedef struct _IMAGE_DATA_DIRECTORY
	{
		ULONG VirtualAddress;
		ULONG Size;
	} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;


	typedef struct _IMAGE_OPTIONAL_HEADER {
		WORD                 Magic;
		BYTE                 MajorLinkerVersion;
		BYTE                 MinorLinkerVersion;
		DWORD                SizeOfCode;
		DWORD                SizeOfInitializedData;
		DWORD                SizeOfUninitializedData;
		DWORD                AddressOfEntryPoint;
		DWORD                BaseOfCode;
		DWORD                BaseOfData;
		DWORD                ImageBase;
		DWORD                SectionAlignment;
		DWORD                FileAlignment;
		WORD                 MajorOperatingSystemVersion;
		WORD                 MinorOperatingSystemVersion;
		WORD                 MajorImageVersion;
		WORD                 MinorImageVersion;
		WORD                 MajorSubsystemVersion;
		WORD                 MinorSubsystemVersion;
		DWORD                Win32VersionValue;
		DWORD                SizeOfImage;
		DWORD                SizeOfHeaders;
		DWORD                CheckSum;
		WORD                 Subsystem;
		WORD                 DllCharacteristics;
		DWORD                SizeOfStackReserve;
		DWORD                SizeOfStackCommit;
		DWORD                SizeOfHeapReserve;
		DWORD                SizeOfHeapCommit;
		DWORD                LoaderFlags;
		DWORD                NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

	typedef struct _IMAGE_OPTIONAL_HEADER64 {
		WORD        Magic;
		BYTE        MajorLinkerVersion;
		BYTE        MinorLinkerVersion;
		DWORD       SizeOfCode;
		DWORD       SizeOfInitializedData;
		DWORD       SizeOfUninitializedData;
		DWORD       AddressOfEntryPoint;
		DWORD       BaseOfCode;
		ULONGLONG   ImageBase;
		DWORD       SectionAlignment;
		DWORD       FileAlignment;
		WORD        MajorOperatingSystemVersion;
		WORD        MinorOperatingSystemVersion;
		WORD        MajorImageVersion;
		WORD        MinorImageVersion;
		WORD        MajorSubsystemVersion;
		WORD        MinorSubsystemVersion;
		DWORD       Win32VersionValue;
		DWORD       SizeOfImage;
		DWORD       SizeOfHeaders;
		DWORD       CheckSum;
		WORD        Subsystem;
		WORD        DllCharacteristics;
		ULONGLONG   SizeOfStackReserve;
		ULONGLONG   SizeOfStackCommit;
		ULONGLONG   SizeOfHeapReserve;
		ULONGLONG   SizeOfHeapCommit;
		DWORD       LoaderFlags;
		DWORD       NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;


	typedef struct _IMAGE_NT_HEADERS32
	{
		ULONG Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER32 OptionalHeader;
	} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

	typedef struct _IMAGE_NT_HEADERS64
	{
		DWORD                   Signature;
		IMAGE_FILE_HEADER       FileHeader;
		IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

#ifdef _WIN64
	typedef IMAGE_NT_HEADERS64  IMAGE_NT_HEADERS;
	typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
	typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
	typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#else
	typedef IMAGE_NT_HEADERS32  IMAGE_NT_HEADERS;
	typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
	typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
	typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#endif

	typedef struct _IMAGE_EXPORT_DIRECTORY {
		DWORD	Characteristics;
		DWORD	TimeDateStamp;
		WORD	MajorVersion;
		WORD	MinorVersion;
		DWORD	Name;
		DWORD	Base;
		DWORD	NumberOfFunctions;
		DWORD	NumberOfNames;
		DWORD	AddressOfFunctions;
		DWORD	AddressOfNames;
		DWORD	AddressOfNameOrdinals;
	} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

	/* Import name entry */
	typedef struct _IMAGE_IMPORT_BY_NAME {
		WORD	Hint;
		BYTE	Name[1];
	} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

#include <pshpack8.h>
	/* Import thunk */
	typedef struct _IMAGE_THUNK_DATA64 {
		union {
			ULONGLONG ForwarderString;
			ULONGLONG Function;
			ULONGLONG Ordinal;
			ULONGLONG AddressOfData;
		} u1;
	} IMAGE_THUNK_DATA64, * PIMAGE_THUNK_DATA64;
#include <poppack.h>

	typedef struct _IMAGE_THUNK_DATA32 {
		union {
			DWORD ForwarderString;
			DWORD Function;
			DWORD Ordinal;
			DWORD AddressOfData;
		} u1;
	} IMAGE_THUNK_DATA32, * PIMAGE_THUNK_DATA32;

	/* Import module directory */

	typedef struct _IMAGE_IMPORT_DESCRIPTOR {
		union {
			DWORD	Characteristics; /* 0 for terminating null import descriptor  */
			DWORD	OriginalFirstThunk;	/* RVA to original unbound IAT */
		} DUMMYUNIONNAME;
		DWORD	TimeDateStamp;	/* 0 if not bound,
					 * -1 if bound, and real date\time stamp
					 *    in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
					 * (new BIND)
					 * otherwise date/time stamp of DLL bound to
					 * (Old BIND)
					 */
		DWORD	ForwarderChain;	/* -1 if no forwarders */
		DWORD	Name;
		/* RVA to IAT (if bound this IAT has actual addresses) */
		DWORD	FirstThunk;
	} IMAGE_IMPORT_DESCRIPTOR, * PIMAGE_IMPORT_DESCRIPTOR;

#define IMAGE_ORDINAL_FLAG64             (((ULONGLONG)0x80000000 << 32) | 0x00000000)
#define IMAGE_ORDINAL_FLAG32             0x80000000
#define IMAGE_SNAP_BY_ORDINAL64(ordinal) (((ordinal) & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(ordinal) (((ordinal) & IMAGE_ORDINAL_FLAG32) != 0)
#define IMAGE_ORDINAL64(ordinal)         ((ordinal) & 0xffff)
#define IMAGE_ORDINAL32(ordinal)         ((ordinal) & 0xffff)

#ifdef _WIN64
#define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG64
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL64(Ordinal)
#define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL64(Ordinal)
	typedef IMAGE_THUNK_DATA64              IMAGE_THUNK_DATA;
	typedef PIMAGE_THUNK_DATA64             PIMAGE_THUNK_DATA;
#else
#define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG32
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL32(Ordinal)
#define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL32(Ordinal)
	typedef IMAGE_THUNK_DATA32              IMAGE_THUNK_DATA;
	typedef PIMAGE_THUNK_DATA32             PIMAGE_THUNK_DATA;
#endif

}