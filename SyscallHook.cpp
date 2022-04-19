#include "Ntdll.h"
#include "SyscallHook.h"
#include "Util.h"

#include <iostream>
#include <fstream>

#include "pin.H"


extern std::ofstream* logging;

std::map<ntdll::PVOID, MEMTRACK> memtrack_lookup;

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
		<< ", " << util::WcharToString((wchar_t*)ObjectAttributes->ObjectName->Buffer)
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
		<< ", " << util::WcharToString((wchar_t*)ObjectAttributes->ObjectName->Buffer)
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
		<< ", " << util::WcharToString((wchar_t*)ObjectAttributes->ObjectName->Buffer)
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
		<< util::WcharToString((wchar_t*)ProcessParameters->CommandLine.Buffer)
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


VOID _HookNtAllocateVirtualMemoryRet(ntdll::NTSTATUS ntstatus, ALLOCTRACK *alloc)
{
	alloc->BaseAddress = *alloc->pBaseAddress;
	alloc->RegionSize = *alloc->pRegionSize;

	*logging << "NtAllocateVirtualMemory" << "("
		<< std::hex << alloc->ProcessHandle
		<< ", " << std::hex << alloc->BaseAddress
		<< ", " << std::hex << alloc->ZeroBits
		<< ", " << std::hex << alloc->RegionSize
		<< ", " << std::hex << alloc->AllocationType
		<< ", " << std::hex << alloc->Protect
		<< ")" << " = " << std::hex << ntstatus
		<< std::endl;

	if (ntstatus == 0) {
		if (memtrack_lookup.count(alloc->BaseAddress) == 0) {
			MEMTRACK track{
				alloc->BaseAddress,
				alloc->RegionSize,
				alloc->Protect
			};
			memtrack_lookup[track.BaseAddress] = track;
		}
	}
}

VOID _HookNtFreeVirtualMemoryRet(ntdll::NTSTATUS ntstatus, FREETRACK *free)
{
	free->BaseAddress = *free->pBaseAddress;
	free->RegionSize = *free->pRegionSize;

	*logging << "NtFreeVirtualMemory" << "("
		<< std::hex << free->ProcessHandle
		<< ", " << std::hex << free->BaseAddress
		<< ", " << std::hex << free->RegionSize
		<< ", " << std::hex << free->FreeType
		<< ")" << " = " << std::hex << ntstatus
		<< std::endl;

	if (ntstatus == 0) {
		if (memtrack_lookup.count(free->BaseAddress) > 0) {
			memtrack_lookup.erase(free->BaseAddress);
		}
	}
}

VOID _HookNtProtectVirtualMemoryRet(ntdll::NTSTATUS ntstatus, PROTECTTRACK *protect)
{
	*logging << "NtProtectVirtualMemory" << "("
		<< std::hex << protect->ProcessHandle
		<< ", " << std::hex << *protect->pBaseAddress
		<< ", " << std::hex << *protect->pRegionSize
		<< ", " << std::hex << protect->NewProtect
		<< ", " << std::hex << *protect->pOldProtect
		<< ")" << " = " << std::hex << ntstatus
		<< std::endl;
}




