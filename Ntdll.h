#pragma once
#include "pin.H"

namespace W {
//#include <windows.h>
}

/* NTDLL shit*/
namespace ntdll {

	typedef unsigned long ULONG;
#if defined(_WIN64)
	typedef unsigned __int64 ULONG_PTR;
#else
	typedef unsigned long ULONG_PTR;
#endif
	typedef ULONG_PTR SIZE_T;
	typedef short SHORT;
	typedef unsigned short USHORT;
	typedef unsigned short WORD;
	typedef unsigned long DWORD;
	typedef long LONG;
#if !defined(_M_IX86)
	typedef __int64 LONGLONG;
#else
	typedef double LONGLONG;
#endif


	typedef CHAR* PCHAR;
	typedef wchar_t  WCHAR;
	typedef WCHAR* PWCHAR;
	typedef const WCHAR* PCWSTR;
	typedef const CHAR* PCSTR;

	typedef VOID* PVOID;
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
	} ANSI_STRING, * PANSI_STRING;


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

}