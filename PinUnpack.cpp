/*
 * Copyright (C) 2007-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */


#include "pin.H"
#include <iostream>
#include <fstream>

#include "Util.h"
#include "Ntdll.h"


ADDRINT gX86SwitchTo64BitMode = 0;

class PinLocker
{
public:
	PinLocker()
	{
		PIN_LockClient();
	}

	~PinLocker()
	{
		PIN_UnlockClient();
	}
};

#ifndef _WIN64
ADDRINT __declspec(naked) X86SwitchTo64BitMode(void)
{
	__asm
	{
		MOV EAX, FS: [0xC0] ; wow64cpu!X86SwitchTo64BitMode
		RET
	}
}
#endif

std::ofstream* logging;


KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
	"o", "", "Specify file name for the output");

/*!
 *  Print out help message.
 */
INT32 Usage()
{
	std::cerr << "Try to unpack next stage by tracking memwrite and rip." << std::endl
		<< std::endl;

	std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

	return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

struct MEMTRACK {
	ntdll::PVOID BaseAddress;
	ntdll::SIZE_T RegionSize;
	ntdll::ULONG Protect;
};

struct FREETRACK {
	ntdll::HANDLE  ProcessHandle;
	ntdll::PVOID BaseAddress;
	ntdll::SIZE_T RegionSize;
	ntdll::ULONG   FreeType;

	// Keep track of the pointer to read them on
	// NtFreeVirtualMemory exit
	ntdll::PVOID* pBaseAddress;
	ntdll::PSIZE_T pRegionSize;
};

struct ALLOCTRACK {
	ntdll::HANDLE    ProcessHandle;
	ntdll::PVOID BaseAddress;
	ntdll::ULONG ZeroBits;
	ntdll::SIZE_T   RegionSize;
	ntdll::ULONG     AllocationType;
	ntdll::ULONG     Protect;

	// Keep track of the pointer to read them on
	// NtAllocateVirtualMemory exit
	ntdll::PVOID* pBaseAddress;
	ntdll::PSIZE_T pRegionSize;
};

struct PROTECTTRACK {
	ntdll::HANDLE  ProcessHandle;
	ntdll::PVOID BaseAddress;
	ntdll::SIZE_T RegionSize;
	ntdll::ULONG NewProtect;
	ntdll::ULONG OldProtect;

	ntdll::PVOID* pBaseAddress;
	ntdll::PSIZE_T pRegionSize;
	ntdll::ULONG* pOldProtect;
};

struct SYSCALLTRACK {
	ntdll::ULONG syscall_number;
	void* data;
};


std::map <THREADID, SYSCALLTRACK> syscall_lookup;

std::map<ntdll::PVOID, MEMTRACK> memtrack_lookup;




#define MAX_SYSCALL (64 * 1024)
const char* g_syscall_names[MAX_SYSCALL] = {  };

void enum_syscalls(ntdll::HMODULE hHandle)
{

	unsigned char* image = (unsigned char*)hHandle;
	ntdll::IMAGE_DOS_HEADER* dos_header = (ntdll::IMAGE_DOS_HEADER*)image;
	ntdll::IMAGE_NT_HEADERS* nt_headers = (ntdll::IMAGE_NT_HEADERS*)(image +
		dos_header->e_lfanew);
	ntdll::IMAGE_DATA_DIRECTORY* data_directory = &nt_headers->
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	ntdll::IMAGE_EXPORT_DIRECTORY* export_directory =
		(ntdll::IMAGE_EXPORT_DIRECTORY*)(image + data_directory->VirtualAddress);
	unsigned long* address_of_names = (unsigned long*)(image +
		export_directory->AddressOfNames);
	unsigned long* address_of_functions = (unsigned long*)(image +
		export_directory->AddressOfFunctions);
	unsigned short* address_of_name_ordinals = (unsigned short*)(image +
		export_directory->AddressOfNameOrdinals);
	unsigned long number_of_names = MIN(export_directory->NumberOfFunctions,
		export_directory->NumberOfNames);
	for (unsigned long i = 0; i < number_of_names; i++) {

		const char* name = (const char*)(image + address_of_names[i]);
		unsigned char* addr = image + address_of_functions[
			address_of_name_ordinals[i]];

		if (!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2)) {
#ifdef _WIN64
			if (*addr == 0x4c && addr[3] == 0xb8) {
				unsigned long syscall_number = *(unsigned long*)(addr + 4);
				if (syscall_number < MAX_SYSCALL) {
					//*logging << syscall_number << " " << name << std::endl;
					g_syscall_names[syscall_number] = name;
				}
			}
#else
			// does the signature match?
			// either:   mov eax, syscall_number ; mov ecx, some_value
			// or:       mov eax, syscall_number ; xor ecx, ecx
			// or:       mov eax, syscall_number ; mov edx, 0x7ffe0300
			if (*addr == 0xb8 &&
				(addr[5] == 0xb9 || addr[5] == 0x33 || addr[5] == 0xba)) {
				unsigned long syscall_number = *(unsigned long*)(addr + 1);
				if (syscall_number < MAX_SYSCALL) {
					//*logging << syscall_number << " " << name << std::endl;
					g_syscall_names[syscall_number] = name;
				}
			}

#endif
		}
	}
}

std::string WcharToString(wchar_t* src) {
	std::wstringstream wss;
	wss << "L\"" << src << "\"";
	std::wstring ws = wss.str();
	return std::string(ws.begin(), ws.end());
}

VOID HookLdrGetProcedureAddress(
	ntdll::HMODULE ModuleHandle,
	ntdll::PANSI_STRING FunctionName,
	ntdll::WORD Ordinal,
	ntdll::PVOID* FunctionAddress
)
{
	PinLocker lock;

	IMG img = IMG_FindByAddress((ADDRINT)ModuleHandle);
	std::string name = "";
	if (img.is_valid()) {
		name = util::getDllName(IMG_Name(img));
	}
	*logging << "LdrGetProcedureAddress" << "("
		<< std::hex << ModuleHandle << " " << name
		<< ", ";

	if (FunctionName != NULL) {
		*logging << FunctionName->Buffer;
	}
	*logging << ", " << Ordinal
		<< ", " << FunctionAddress
		<< ")"
		<< std::endl;
}


void SetupHookNtdll(IMG Image)
{
	const std::string dllName = util::getDllName(IMG_Name(Image));
	if (util::iequals(dllName, "ntdll")) {
		enum_syscalls((ntdll::HMODULE)IMG_StartAddress(Image));

		std::string fns[] = { "LdrGetProcedureAddress", "LdrGetProcedureAddressForCaller" };
		for (const auto& fn : fns) {
			RTN targetRtn = RTN_FindByName(Image, fn.c_str());
			if (targetRtn.is_valid()) {
				*logging << "Hook " << fn << std::endl;
				RTN_Open(targetRtn);
				RTN_InsertCall(targetRtn, IPOINT_BEFORE, (AFUNPTR)HookLdrGetProcedureAddress,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
					IARG_END);
				RTN_Close(targetRtn);
			}
		}

#ifndef _WIN64
		gX86SwitchTo64BitMode = X86SwitchTo64BitMode();

		if (gX86SwitchTo64BitMode == 0) {
			ntdll::LdrLoadDll pLdrLoadDll = (ntdll::LdrLoadDll)RTN_Funptr(RTN_FindByName(Image, "LdrLoadDll"));
			ntdll::LdrGetProcedureAddress pLdrGetProcedureAddress = (ntdll::LdrGetProcedureAddress)RTN_Funptr(RTN_FindByName(Image, "LdrGetProcedureAddress"));
			ntdll::RtlInitUnicodeString pRtlInitUnicodeString = (ntdll::RtlInitUnicodeString)RTN_Funptr(RTN_FindByName(Image, "RtlInitUnicodeString"));
			ntdll::RtlInitAnsiString pRtlInitAnsiString = (ntdll::RtlInitAnsiString)RTN_Funptr(RTN_FindByName(Image, "RtlInitAnsiString"));
			/**logging << "LdrLoadDll @ " << std::hex << pLdrLoadDll << std::endl
				<< "LdrGetProcedureAddress @ " << std::hex << pLdrGetProcedureAddress << std::endl
				<< "RtlInitUnicodeString @ " << std::hex << pRtlInitUnicodeString << std::endl
				<< "RtlInitAnsiString @ " << std::hex << pRtlInitAnsiString << std::endl;*/

			ntdll::ANSI_STRING fn;
			pRtlInitAnsiString(&fn, "Wow64Transition");

			void* pWow64Transition = 0;
			pWow64Transition = (void*)RTN_Funptr(RTN_FindByName(Image, "Wow64Transition"));
			pLdrGetProcedureAddress((VOID*)IMG_StartAddress(Image), &fn, 0, &pWow64Transition);

			if (pWow64Transition != 0) {
				gX86SwitchTo64BitMode = *(ADDRINT*)pWow64Transition;
			}

			*logging << "Wow64Transition @" << std::hex << pWow64Transition << std::endl;
		}

		*logging << "X86SwitchTo64BitMode @" << std::hex << gX86SwitchTo64BitMode << std::endl;
#endif
	}
}



/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */


std::string to_hex_string(const ADDRINT i) {
	return (static_cast<std::stringstream const&>(std::stringstream() << std::hex << i)).str();
}

VOID Transitions(const ADDRINT prevVA, const ADDRINT Address, BOOL isIndirect, const CONTEXT* ctx)
{
	PinLocker locker;

	IMG callerModule = IMG_FindByAddress(prevVA);
	IMG targetModule = IMG_FindByAddress(Address);

	if (callerModule == targetModule) {
		return;
	}

	bool isCallerPeModule = IMG_Valid(callerModule);
	bool isTargetPeModule = IMG_Valid(targetModule);

	std::string callerName = to_hex_string(prevVA);
	std::string targetName = to_hex_string(Address);

	if (isCallerPeModule) {
		callerName = util::getDllName(IMG_Name(callerModule));
	}

	if (isTargetPeModule) {
		targetName = util::getDllName(IMG_Name(targetModule));
	}

	if (gX86SwitchTo64BitMode && gX86SwitchTo64BitMode == Address) {
		isTargetPeModule = true;
	}

	if (!isCallerPeModule || !isTargetPeModule) {
		*logging << callerName << " -> " << targetName << std::endl;
		//out << std::hex << prevVA << " -> " << std::hex << Address << std::endl;
	}
}


VOID Instruction(INS ins, VOID* v)
{
	if ((INS_IsControlFlow(ins) || INS_IsFarJump(ins))) {
		BOOL isIndirect = INS_IsIndirectControlFlow(ins) && !INS_IsRet(ins);
		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)Transitions,
			IARG_INST_PTR,
			IARG_BRANCH_TARGET_ADDR,
			IARG_BOOL, isIndirect,
			IARG_CONTEXT,
			IARG_END
		);
	}
}

VOID* _HookNtCreateFile(
	ntdll::PHANDLE            FileHandle,
	ntdll::ACCESS_MASK        DesiredAccess,
	ntdll::POBJECT_ATTRIBUTES ObjectAttributes,
	ntdll::PIO_STATUS_BLOCK   IoStatusBlock,
	ntdll::PLARGE_INTEGER     AllocationSize,
	ntdll::ULONG              FileAttributes,
	ntdll::ULONG              ShareAccess,
	ntdll::ULONG              CreateDisposition,
	ntdll::ULONG              CreateOptions,
	ntdll::PVOID              EaBuffer,
	ntdll::ULONG              EaLength
)
{
	*logging << "NtCreateFile" << "("
		<< std::hex << *FileHandle
		<< ", " << std::hex << DesiredAccess
		<< ", " << WcharToString((wchar_t*)ObjectAttributes->ObjectName->Buffer)
		<< ", " << std::hex << IoStatusBlock
		<< ", " << std::hex << AllocationSize
		<< ", " << std::hex << FileAttributes
		<< ", " << std::hex << ShareAccess
		<< ", " << std::hex << CreateDisposition
		<< ", " << std::hex << CreateOptions
		<< ", " << std::hex << EaBuffer
		<< ", " << std::hex << EaLength
		<< ")"
		<< std::endl;

	return NULL;
}

VOID* _HookNtOpenFile(
	ntdll::PHANDLE            FileHandle,
	ntdll::ACCESS_MASK        DesiredAccess,
	ntdll::POBJECT_ATTRIBUTES ObjectAttributes,
	ntdll::PIO_STATUS_BLOCK   IoStatusBlock,
	ntdll::ULONG              ShareAccess,
	ntdll::ULONG              OpenOptions
)
{
	*logging << "NtOpenFile" << "("
		<< std::hex << *FileHandle
		<< ", " << std::hex << DesiredAccess
		<< ", " << WcharToString((wchar_t*)ObjectAttributes->ObjectName->Buffer)
		<< ", " << std::hex << IoStatusBlock
		<< ", " << std::hex << ShareAccess
		<< ", " << std::hex << OpenOptions
		<< ")"
		<< std::endl;

	return NULL;
}

VOID* _HookNtOpenProcess(
	ntdll::PHANDLE            ProcessHandle,
	ntdll::ACCESS_MASK        DesiredAccess,
	ntdll::POBJECT_ATTRIBUTES ObjectAttributes,
	ntdll::PCLIENT_ID         ClientId
)
{
	*logging << "NtOpenProcess" << "("
		<< std::hex << DesiredAccess
		<< ", " << ClientId->UniqueProcess
		<< ")" << std::endl;

	return NULL;
}

VOID* _HookNtCreateProcess(
	ntdll::PHANDLE ProcessHandle,
	ntdll::ACCESS_MASK DesiredAccess,
	ntdll::POBJECT_ATTRIBUTES ObjectAttributes,
	ntdll::HANDLE ParentProcess,
	BOOL InheritObjectTable,
	ntdll::HANDLE SectionHandle,
	ntdll::HANDLE DebugPort,
	ntdll::HANDLE ExceptionPort
)
{
	*logging << "NtCreateProcess" << "("
		<< std::hex << DesiredAccess
		<< ", " << WcharToString((wchar_t*)ObjectAttributes->ObjectName->Buffer)
		<< ")" << std::endl;

	return NULL;
}

VOID* _HookNtCreateUserProcess(
	ntdll::PHANDLE ProcessHandle,
	ntdll::PHANDLE ThreadHandle,
	ntdll::ACCESS_MASK ProcessDesiredAccess,
	ntdll::ACCESS_MASK ThreadDesiredAccess,
	ntdll::POBJECT_ATTRIBUTES ProcessObjectAttributes,
	ntdll::POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ntdll::ULONGLONG ProcessFlags,
	ntdll::ULONGLONG ThreadFlags,
	ntdll::PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	ntdll::PVOID CreateInfo,
	ntdll::PVOID AttributeList)
{
	*logging << "_HookCreateUserProcess" << "("
		<< WcharToString((wchar_t*)ProcessParameters->CommandLine.Buffer)
		<< ")" << std::endl;
	return NULL;
}

VOID* _NtCreateThread(
	ntdll::PHANDLE ThreadHandle,
	ntdll::ACCESS_MASK DesiredAccess,
	ntdll::POBJECT_ATTRIBUTES ObjectAttributes,
	ntdll::HANDLE ProcessHandle,
	ntdll::PCLIENT_ID ClientId,
	ntdll::PVOID ThreadContext,
	ntdll::PVOID InitialTeb,
	BOOL CreateSuspended)
{
	*logging << "NtCreateThread" << "("
		<< std::hex << ThreadHandle
		<< ", " << std::hex << DesiredAccess
		<< ", " << std::hex << ObjectAttributes
		<< ", " << std::hex << ProcessHandle
		<< ", " << std::hex << ClientId
		<< ", " << std::hex << ThreadContext
		<< ", " << std::hex << InitialTeb
		<< ", " << CreateSuspended
		<< ")" << std::endl;

	return NULL;
}

VOID* _NtCreateThreadEx(
	ntdll::PHANDLE ThreadHandle,
	ntdll::ACCESS_MASK DesiredAccess,
	ntdll::POBJECT_ATTRIBUTES ObjectAttributes,
	ntdll::HANDLE ProcessHandle,
	ntdll::LPTHREAD_START_ROUTINE StartRoutine,
	ntdll::PVOID Argument,
	BOOL CreateSuspended,
	ntdll::ULONG_PTR ZeroBits,
	ntdll::SIZE_T StackSize,
	ntdll::SIZE_T MaximumStackSize,
	ntdll::PVOID AttributeList)
{
	*logging << "NtCreateThreadEx" << "("
		<< std::hex << ThreadHandle
		<< ", " << std::hex << DesiredAccess
		<< ", " << std::hex << ObjectAttributes
		<< ", " << std::hex << ProcessHandle
		<< ", " << std::hex << StartRoutine
		<< ", " << std::hex << Argument
		<< ", " << std::hex << CreateSuspended
		<< "..."
		<< ")" << std::endl;

	return NULL;
}

VOID* _HookNtAllocateVirtualMemory(
	ntdll::HANDLE    ProcessHandle,
	ntdll::PVOID* BaseAddress,
	ntdll::ULONG_PTR ZeroBits,
	ntdll::PSIZE_T   RegionSize,
	ntdll::ULONG     AllocationType,
	ntdll::ULONG     Protect)
{

	ALLOCTRACK* alloc = new ALLOCTRACK{
		ProcessHandle,
		*BaseAddress,
		0,
		*RegionSize,
		AllocationType,
		Protect,
		BaseAddress,
		RegionSize
	};

	/*if (ZeroBits != NULL) {
		alloc.ZeroBits = *ZeroBits;
	}*/

	return alloc;
}

VOID* _HookNtFreeVirtualMemory(
	ntdll::HANDLE  ProcessHandle,
	ntdll::PVOID* BaseAddress,
	ntdll::PSIZE_T RegionSize,
	ntdll::ULONG   FreeType)
{
	FREETRACK* free = new FREETRACK{
		ProcessHandle,
		*BaseAddress,
		*RegionSize,
		FreeType,

		BaseAddress,
		RegionSize,
	};

	return free;
}

VOID* _HookNtProtectVirtualMemory(
	ntdll::HANDLE  ProcessHandle,
	ntdll::PVOID* BaseAddress,
	ntdll::PSIZE_T RegionSize,
	ntdll::ULONG NewProtect,
	ntdll::ULONG* OldProtect)
{
	PROTECTTRACK* protect = new PROTECTTRACK{
		ProcessHandle,
		*BaseAddress,
		*RegionSize,
		NewProtect,
		*OldProtect,
		BaseAddress,
		RegionSize,
		OldProtect
	};

	return protect;
}


VOID _HookNtAllocateVirtualMemoryRet(ntdll::NTSTATUS ntstatus, ALLOCTRACK alloc)
{
	alloc.BaseAddress = *alloc.pBaseAddress;
	alloc.RegionSize = *alloc.pRegionSize;

	*logging << "NtAllocateVirtualMemory" << "("
		<< std::hex << alloc.ProcessHandle
		<< ", " << std::hex << alloc.BaseAddress
		<< ", " << std::hex << alloc.ZeroBits
		<< ", " << std::hex << alloc.RegionSize
		<< ", " << std::hex << alloc.AllocationType
		<< ", " << std::hex << alloc.Protect
		<< ")" << " = " << std::hex << ntstatus
		<< std::endl;

	if (ntstatus == 0) {
		if (memtrack_lookup.count(alloc.BaseAddress) == 0) {
			MEMTRACK track{
				alloc.BaseAddress,
				alloc.RegionSize,
				alloc.Protect
			};
			memtrack_lookup[track.BaseAddress] = track;
		}
	}
}

VOID _HookNtFreeVirtualMemoryRet(ntdll::NTSTATUS ntstatus, FREETRACK free)
{
	free.BaseAddress = *free.pBaseAddress;
	free.RegionSize = *free.pRegionSize;

	*logging << "NtFreeVirtualMemory" << "("
		<< std::hex << free.ProcessHandle
		<< ", " << std::hex << free.BaseAddress
		<< ", " << std::hex << free.RegionSize
		<< ", " << std::hex << free.FreeType
		<< ")" << " = " << std::hex << ntstatus
		<< std::endl;

	if (ntstatus == 0) {
		if (memtrack_lookup.count(free.BaseAddress) > 0) {
			memtrack_lookup.erase(free.BaseAddress);
		}
	}
}

VOID _HookNtProtectVirtualMemoryRet(ntdll::NTSTATUS ntstatus, PROTECTTRACK protect)
{
	*logging << "NtProtectVirtualMemory" << "("
		<< std::hex << protect.ProcessHandle
		<< ", " << std::hex << *protect.pBaseAddress
		<< ", " << std::hex << *protect.pRegionSize
		<< ", " << std::hex << protect.NewProtect
		<< ", " << std::hex << *protect.pOldProtect
		<< ")" << " = " << std::hex << ntstatus
		<< std::endl;
}

typedef void* (__stdcall* FnSyscallInterceptExit)(
	ntdll::NTSTATUS ntstatus, void* data);

typedef void* (__stdcall* FnSyscallIntercept4)(
	void* arg1, void* arg2, void* arg3, void* arg4);

typedef void* (__stdcall* FnSyscallIntercept5)(
	void* arg1, void* arg2, void* arg3, void* arg4,
	void* arg5);

typedef void* (__stdcall* FnSyscallIntercept6)(
	void* arg1, void* arg2, void* arg3, void* arg4,
	void* arg5, void* arg6);

typedef void* (__stdcall* FnSyscallIntercept8)(
	void* arg1, void* arg2, void* arg3, void* arg4,
	void* arg5, void* arg6, void* arg7, void* arg8);

typedef void* (__stdcall* FnSyscallIntercept11)(
	void* arg1, void* arg2, void* arg3, void* arg4,
	void* arg5, void* arg6, void* arg7, void* arg8,
	void* arg9, void* arg10, void* arg11);

struct SyscallIntercept {
	char szFunctionName[128];
	int nParam;
	void* syscallCB;
};

SyscallIntercept InterceptEntry[]{
	{"ZwOpenFile", 6, _HookNtOpenFile},
	{"ZwCreateFile", 11, _HookNtCreateFile},
	{"ZwOpenProcess", 4, _HookNtOpenProcess},
	{"ZwCreateProcess", 8, _HookNtCreateProcess},
	{"ZwCreateProcessEx", 8, _HookNtCreateProcess},
	{"ZwCreateUserProcess", 11, _HookNtCreateUserProcess},
	{"ZwAllocateVirtualMemory", 6, _HookNtAllocateVirtualMemory},
	{"ZwProtectVirtualMemory", 5, _HookNtProtectVirtualMemory},
	{"ZwFreeVirtualMemory", 4, _HookNtFreeVirtualMemory},
	{"NtCreateThread", 8, _NtCreateThread},
	{"NtCreateThreadEx", 8, _NtCreateThreadEx},
};

SyscallIntercept InterceptExit[]{
	{"ZwAllocateVirtualMemory", 1, _HookNtAllocateVirtualMemoryRet},
	{"ZwProtectVirtualMemory", 1, _HookNtProtectVirtualMemoryRet},
	{"ZwFreeVirtualMemory", 1, _HookNtFreeVirtualMemoryRet},
};

void SyscallExit(
	THREADID thread_id,
	CONTEXT* ctx,
	SYSCALL_STANDARD std,
	void* v)
{
	PinLocker lock;
	
	if (syscall_lookup.count(thread_id) == 0) {
		*logging << "Syscall lookup error, "
			<< std::hex << thread_id << " not found" << std::endl;
		return;
	}
	
	SYSCALLTRACK st = syscall_lookup[thread_id];
	if (st.syscall_number < MAX_SYSCALL) {
		const char* name = g_syscall_names[st.syscall_number];
		if (name != NULL) {
			for (const auto& e : InterceptExit) {
				if (strcmp(name, e.szFunctionName) == 0) {
					ADDRINT ret = PIN_GetSyscallReturn(ctx, std);

					/**logging << "thread_id: " << thread_id
						<< "\tsyscall: " << st.syscall_number
						<< "\tname: " << name
						<< "\tret: " << ret
						<< std::endl;*/

					switch (e.nParam) {
					case 1:
						((FnSyscallInterceptExit)e.syscallCB)(ret, (void*)st.data);
						break;
					}
				}
			}
		}
	}

	if (st.data != NULL) {
		delete st.data;
	}

	syscall_lookup.erase(thread_id);
}

void SyscallEntry(
	THREADID thread_id,
	CONTEXT* ctx,
	SYSCALL_STANDARD std,
	void* v)
{
	PinLocker lock;

	ADDRINT  syscall_number = PIN_GetSyscallNumber(ctx, std);



	SYSCALLTRACK st{ syscall_number, NULL };
	
	if (syscall_number < MAX_SYSCALL) {
		const char* name = g_syscall_names[syscall_number];
		if (name != NULL) {
			for (const auto& e : InterceptEntry) {
				if (strcmp(name, e.szFunctionName) == 0) {

					void* args[12];
					for (int j = 0; j < e.nParam; j++) {
						args[j] = (void*)PIN_GetSyscallArgument(ctx, std, j);
					}

					switch (e.nParam) {
					case 4:
						st.data = ((FnSyscallIntercept4)e.syscallCB)(args[0], args[1], args[2], args[3]);
						break;
					case 5:
						st.data = ((FnSyscallIntercept6)e.syscallCB)(args[0], args[1], args[2], args[3], args[4], args[5]);
						break;
					case 6:
						st.data = ((FnSyscallIntercept6)e.syscallCB)(args[0], args[1], args[2], args[3], args[4], args[5]);
						break;
					case 8:
						st.data = ((FnSyscallIntercept8)e.syscallCB)(args[0], args[1], args[2], args[3], args[4], args[5],
							args[6], args[7]);
					case 11:
						st.data = ((FnSyscallIntercept11)e.syscallCB)(args[0], args[1], args[2], args[3], args[4], args[5],
							args[6], args[7], args[8], args[9], args[10]);
						break;
					}
				}
			}
		}
	}
	
	if (syscall_lookup.count(thread_id) != NULL) {
		*logging << "orphelan syscall lookup" << std::endl;
		if (syscall_lookup[thread_id].data != NULL) {
			delete syscall_lookup[thread_id].data;
		}

		syscall_lookup.erase(thread_id);
	}
	syscall_lookup[thread_id] = st;
	
}

VOID ImageLoad(IMG Image, VOID* v)
{
	PinLocker locker;

	const std::string dllName = util::getDllName(IMG_Name(Image));

	*logging << dllName << " @ " << std::hex << IMG_LoadOffset(Image) << std::endl;

	SetupHookNtdll(Image);
}


int main(int argc, char* argv[])
{
	PIN_InitSymbols();

	if (PIN_Init(argc, argv))
	{
		return Usage();
	}


	IMG_AddInstrumentFunction(ImageLoad, NULL);
	INS_AddInstrumentFunction(Instruction, NULL);

	PIN_AddSyscallEntryFunction(SyscallEntry, NULL);
	PIN_AddSyscallExitFunction(SyscallExit, NULL);

	std::cerr << "===============================================" << std::endl;
	std::cerr << "This application is instrumented by PinUnpack" << std::endl;
	if (!KnobOutputFile.Value().empty())
	{
		std::cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << std::endl;
		logging = new std::ofstream(KnobOutputFile.Value().c_str());
	}

	std::cerr << "===============================================" << std::endl;

	PIN_StartProgram();

	return 0;
}