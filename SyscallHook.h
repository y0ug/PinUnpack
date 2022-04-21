#pragma once

#include "pin.H"
#include "Ntdll.h"

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

#define MAX_SYSCALL (64 * 1024)

class SyscallNameMap
{

private:
	const char* _syscall_names[MAX_SYSCALL] = {  };

public:
	SyscallNameMap()
	{

	}

	~SyscallNameMap() {}

	const char* getName(unsigned long syscall_number) {
		if (syscall_number < MAX_SYSCALL) {
			return this->_syscall_names[syscall_number];
		}
		return NULL;
	}

	void load(ntdll::HMODULE hHandle)
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
						this->_syscall_names[syscall_number] = name;
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
						this->_syscall_names[syscall_number] = name;
					}
				}
#endif
			}
		}
	}
};

struct MEMTRACK {
	ntdll::PVOID BaseAddress;
	ntdll::SIZE_T RegionSize;
	ntdll::ULONG Protect;
	BOOL isDump;
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

VOID* _HookNtCreateFile(ntdll::PHANDLE FileHandle, ntdll::ACCESS_MASK DesiredAccess, ntdll::POBJECT_ATTRIBUTES ObjectAttributes, ntdll::PIO_STATUS_BLOCK IoStatusBlock, ntdll::PLARGE_INTEGER AllocationSize, ntdll::ULONG FileAttributes, ntdll::ULONG ShareAccess, ntdll::ULONG CreateDisposition, ntdll::ULONG CreateOptions, ntdll::PVOID EaBuffer, ntdll::ULONG EaLength);

VOID* _HookNtOpenFile(ntdll::PHANDLE FileHandle, ntdll::ACCESS_MASK DesiredAccess, ntdll::POBJECT_ATTRIBUTES ObjectAttributes, ntdll::PIO_STATUS_BLOCK IoStatusBlock, ntdll::ULONG ShareAccess, ntdll::ULONG OpenOptions);

VOID* _HookNtOpenProcess(ntdll::PHANDLE ProcessHandle, ntdll::ACCESS_MASK DesiredAccess, ntdll::POBJECT_ATTRIBUTES ObjectAttributes, ntdll::PCLIENT_ID ClientId);

VOID* _HookNtCreateProcess(ntdll::PHANDLE ProcessHandle, ntdll::ACCESS_MASK DesiredAccess, ntdll::POBJECT_ATTRIBUTES ObjectAttributes, ntdll::HANDLE ParentProcess, BOOL InheritObjectTable, ntdll::HANDLE SectionHandle, ntdll::HANDLE DebugPort, ntdll::HANDLE ExceptionPort);

VOID* _HookNtCreateUserProcess(ntdll::PHANDLE ProcessHandle, ntdll::PHANDLE ThreadHandle, ntdll::ACCESS_MASK ProcessDesiredAccess, ntdll::ACCESS_MASK ThreadDesiredAccess, ntdll::POBJECT_ATTRIBUTES ProcessObjectAttributes, ntdll::POBJECT_ATTRIBUTES ThreadObjectAttributes, ntdll::ULONGLONG ProcessFlags, ntdll::ULONGLONG ThreadFlags, ntdll::PRTL_USER_PROCESS_PARAMETERS ProcessParameters, ntdll::PVOID CreateInfo, ntdll::PVOID AttributeList);

VOID* _NtCreateThread(ntdll::PHANDLE ThreadHandle, ntdll::ACCESS_MASK DesiredAccess, ntdll::POBJECT_ATTRIBUTES ObjectAttributes, ntdll::HANDLE ProcessHandle, ntdll::PCLIENT_ID ClientId, ntdll::PVOID ThreadContext, ntdll::PVOID InitialTeb, BOOL CreateSuspended);

VOID* _NtCreateThreadEx(ntdll::PHANDLE ThreadHandle, ntdll::ACCESS_MASK DesiredAccess, ntdll::POBJECT_ATTRIBUTES ObjectAttributes, ntdll::HANDLE ProcessHandle, ntdll::LPTHREAD_START_ROUTINE StartRoutine, ntdll::PVOID Argument, BOOL CreateSuspended, ntdll::ULONG_PTR ZeroBits, ntdll::SIZE_T StackSize, ntdll::SIZE_T MaximumStackSize, ntdll::PVOID AttributeList);

VOID* _HookNtAllocateVirtualMemory(ntdll::HANDLE ProcessHandle, ntdll::PVOID* BaseAddress, ntdll::ULONG_PTR ZeroBits, ntdll::PSIZE_T RegionSize, ntdll::ULONG AllocationType, ntdll::ULONG Protect);

VOID* _HookNtFreeVirtualMemory(ntdll::HANDLE ProcessHandle, ntdll::PVOID* BaseAddress, ntdll::PSIZE_T RegionSize, ntdll::ULONG FreeType);

VOID* _HookNtProtectVirtualMemory(ntdll::HANDLE ProcessHandle, ntdll::PVOID* BaseAddress, ntdll::PSIZE_T RegionSize, ntdll::ULONG NewProtect, ntdll::ULONG* OldProtect);

VOID _HookNtAllocateVirtualMemoryRet(ntdll::NTSTATUS ntstatus, ALLOCTRACK *alloc);

VOID _HookNtFreeVirtualMemoryRet(ntdll::NTSTATUS ntstatus, FREETRACK *free);

VOID _HookNtProtectVirtualMemoryRet(ntdll::NTSTATUS ntstatus, PROTECTTRACK *protect);
