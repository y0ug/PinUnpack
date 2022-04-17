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

std::ofstream*logging;


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
    ADDRINT BaseAddress;
    uint64_t RegionSize;
    uint32_t Protect;
};

struct FREETRACK {
    ADDRINT ProcessHandle;
    ADDRINT BaseAddress;
    ADDRINT RegionSize;
    uint32_t FreeType;

    // Keep track of the pointer to read them on
    // NtFreeVirtualMemory exit
    ADDRINT* pBaseAddress;
    ADDRINT* pRegionSize;
};

struct ALLOCTRACK {
    ADDRINT ProcessHandle;
    ADDRINT BaseAddress;
    uint64_t ZeroBits;
    ADDRINT RegionSize;
    uint32_t AllocationType;
    uint32_t Protect;

    // Keep track of the pointer to read them on
    // NtAllocateVirtualMemory exit
    ADDRINT* pBaseAddress;
    ADDRINT* pRegionSize;
};

struct PROTECTTRACK {
    ADDRINT  ProcessHandle;
    ADDRINT BaseAddress;
    ADDRINT RegionSize;
    uint32_t NewProtect;
    uint32_t OldProtect;

    ADDRINT* pBaseAddress;
    ADDRINT* pRegionSize;
    uint32_t* pOldProtect;
};

std::map<OS_THREAD_ID, ALLOCTRACK> ntallocate_lookup;
std::map<OS_THREAD_ID, FREETRACK> ntfree_lookup;
std::map<OS_THREAD_ID, PROTECTTRACK> ntprotect_lookup;

std::map<ADDRINT, MEMTRACK> memtrack_lookup;

VOID HookNtAllocateVirtualMemory(
    ADDRINT   ProcessHandle,
    ADDRINT* BaseAddress,
    ADDRINT* ZeroBits,
    ADDRINT* RegionSize,
    uint32_t   AllocationType,
    uint32_t   Protect)
{
    OS_THREAD_ID tid = PIN_GetTid();

    ALLOCTRACK alloc{
        ProcessHandle,
        *BaseAddress,
        0,
        *RegionSize,
        AllocationType,
        Protect,
        BaseAddress,
        RegionSize
    };

    if (ZeroBits != NULL) {
        alloc.ZeroBits = *ZeroBits;
    }

    ntallocate_lookup[tid] = alloc;
}

VOID HookNtAllocateVirtualMemoryReturn(uint32_t ntstatus)
{
    OS_THREAD_ID tid = PIN_GetTid();

    if (ntallocate_lookup.count(tid) == 0) {
        *logging << "HookNtAllocateVirtualMemoryReturn error, " 
            << std::hex << tid << " not found" << std::endl;
        return;
    }
    ALLOCTRACK alloc = ntallocate_lookup[tid];
    alloc.BaseAddress = *alloc.pBaseAddress;
    alloc.RegionSize = *alloc.pRegionSize;

    *logging << tid << " "
        << "NtAllocateVirtualMemory" << "("
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

    ntallocate_lookup.erase(tid);
}

VOID HookNtFreeVirtualMemory(
    ADDRINT   ProcessHandle,
    ADDRINT* BaseAddress,
    ADDRINT* RegionSize,
    uint32_t   FreeType)
{
    OS_THREAD_ID tid = PIN_GetTid();
    
    FREETRACK free{
        ProcessHandle,
        *BaseAddress,
        *RegionSize,
        FreeType,

        BaseAddress,
        RegionSize,
    };

    ntfree_lookup[tid] = free;
}

VOID HookNtFreeVirtualMemoryReturn(uint32_t ntstatus)
{
    OS_THREAD_ID tid = PIN_GetTid();

    if (ntfree_lookup.count(tid) == 0) {
        *logging << "HookNtFreeVirtualMemoryReturn error, "
            << std::hex << tid << " not found" << std::endl;
        return;
    }

    FREETRACK free = ntfree_lookup[tid];
    free.BaseAddress = *free.pBaseAddress;
    free.RegionSize = *free.pRegionSize;

    *logging << tid << " "
        << "NtFreeVirtualMemory" << "("
        << std::hex << free.ProcessHandle
        << ", " << std::hex << free.BaseAddress
        << ", " << std::hex << free.RegionSize
        << ", " << std::hex << free.FreeType
        << ")" << " = " << std::hex << ntstatus
        << std::endl;

    if(ntstatus == 0){
        if (memtrack_lookup.count(free.BaseAddress) > 0) {
            memtrack_lookup.erase(free.BaseAddress);
        }
    }

    ntfree_lookup.erase(tid);
}


VOID HookNtProtectVirtualMemory(
    ADDRINT  ProcessHandle,
    ADDRINT* BaseAddress,
    ADDRINT* RegionSize,
    uint32_t NewProtect,
    uint32_t* OldProtect)
{
    OS_THREAD_ID tid = PIN_GetTid();

    PROTECTTRACK protect{
        ProcessHandle,
        *BaseAddress,
        *RegionSize,
        NewProtect,
        *OldProtect,
        BaseAddress,
        RegionSize,
        OldProtect
    };

    ntprotect_lookup[tid] = protect;
}

 VOID HookNtProtectVirtualMemoryReturn(ntdll::NTSTATUS ntstatus){
    OS_THREAD_ID tid = PIN_GetTid();

    if (ntprotect_lookup.count(tid) == 0) {
        *logging << "HookNtFreeVirtualMemoryReturn error, "
            << std::hex << tid << " not found" << std::endl;
        return;
    }

    PROTECTTRACK protect = ntprotect_lookup[tid];

    /*out << tid << " "
        << "NtProtectVirtualMemory" << "("
        << std::hex << protect.ProcessHandle
        << ", " << std::hex << *protect.pBaseAddress
        << ", " << std::hex << *protect.pRegionSize
        << ", " << std::hex << protect.NewProtect
        << ", " << std::hex << *protect.pOldProtect
        << ")" << " = " << std::hex << ntstatus
        << std::endl;*/

    ntprotect_lookup.erase(tid);
}

 std::string WcharToString(wchar_t* src) {
     std::wstringstream wss;
     wss << "L\"" << src << "\"";
     std::wstring ws = wss.str();
     return std::string(ws.begin(), ws.end());
 }

 VOID HookNtOpenFile(
    ntdll::PHANDLE            FileHandle,
    ntdll::ACCESS_MASK        DesiredAccess,
    ntdll::POBJECT_ATTRIBUTES ObjectAttributes,
    ntdll::PIO_STATUS_BLOCK   IoStatusBlock,
    ntdll::ULONG              ShareAccess,
    ntdll::ULONG              OpenOptions
 ) 
 {
     OS_THREAD_ID tid = PIN_GetTid();

     *logging << tid << " "
         << "NtOpenFile" << "("
         << std::hex << *FileHandle
         << ", " << std::hex << DesiredAccess
         << ", " << WcharToString((wchar_t*)ObjectAttributes->ObjectName->Buffer)
         << ", " << std::hex << IoStatusBlock
         << ", " << std::hex << ShareAccess
         << ", " << std::hex << OpenOptions
         << ")" 
         << std::endl;
 }

 VOID HookNtCreateFile(
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
     OS_THREAD_ID tid = PIN_GetTid();

     *logging << tid << " "
         << "NtCreateFile" << "("
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
 }

 VOID HookLdrGetProcedureAddress(
     ntdll::HMODULE ModuleHandle,
     ntdll::PANSI_STRING FunctionName,
     ntdll::WORD Ordinal,
     ntdll::PVOID* FunctionAddress
 )
 {
     OS_THREAD_ID tid = PIN_GetTid();

     PinLocker lock;
     IMG img = IMG_FindByAddress((ADDRINT)ModuleHandle);
     std::string name = "";
     if (img.is_valid()) {
         name = util::getDllName(IMG_Name(img));
     }
     *logging << tid << " "
         << "LdrGetProcedureAddress" << "("
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
        RTN targetRtn = RTN_FindByName(Image, "NtAllocateVirtualMemory");
        if (targetRtn.is_valid()) {
            *logging << "Hook NtAllocateVirtualMemory" << std::endl;
            RTN_Open(targetRtn);
            RTN_InsertCall(targetRtn, IPOINT_BEFORE, (AFUNPTR)HookNtAllocateVirtualMemory,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);

            RTN_InsertCall(targetRtn, IPOINT_AFTER, (AFUNPTR)HookNtAllocateVirtualMemoryReturn,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);

            RTN_Close(targetRtn);
        }

        targetRtn = RTN_FindByName(Image, "NtFreeVirtualMemory");
        if (targetRtn.is_valid()) {
            *logging << "Hook NtFreeVirtualMemory" << std::endl;
            RTN_Open(targetRtn);
            RTN_InsertCall(targetRtn, IPOINT_BEFORE, (AFUNPTR)HookNtFreeVirtualMemory,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);

            RTN_InsertCall(targetRtn, IPOINT_AFTER, (AFUNPTR)HookNtFreeVirtualMemoryReturn,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);
            RTN_Close(targetRtn);
        }

        targetRtn = RTN_FindByName(Image, "NtOpenFile");
        if (targetRtn.is_valid()) {
            *logging << "Hook NtOpenFile  " << std::endl;
            RTN_Open(targetRtn);
            RTN_InsertCall(targetRtn, IPOINT_BEFORE, (AFUNPTR)HookNtOpenFile,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                IARG_END);
            RTN_Close(targetRtn);
        }

        targetRtn = RTN_FindByName(Image, "NtCreateFile");
        if (targetRtn.is_valid()) {
            *logging << "Hook NtCreateFile  " << std::endl;
            RTN_Open(targetRtn);
            RTN_InsertCall(targetRtn, IPOINT_BEFORE, (AFUNPTR)HookNtCreateFile,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 7, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
                IARG_END);
            RTN_Close(targetRtn);
        }

        targetRtn = RTN_FindByName(Image, "NtProtectVirtualMemory");
        if (targetRtn.is_valid()) {
            *logging << "Hook NtProtectVirtualMemory  " << std::endl;
            RTN_Open(targetRtn);
            RTN_InsertCall(targetRtn, IPOINT_BEFORE, (AFUNPTR)HookNtProtectVirtualMemory,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                IARG_END);

            RTN_InsertCall(targetRtn, IPOINT_AFTER, (AFUNPTR)HookNtProtectVirtualMemoryReturn,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);
            RTN_Close(targetRtn);
        }
        
        targetRtn = RTN_FindByName(Image, "LdrGetProcedureAddress");
        if (targetRtn.is_valid()) {
            *logging << "Hook LdrGetProcedureAddress  " << std::endl;
            RTN_Open(targetRtn);
            RTN_InsertCall(targetRtn, IPOINT_BEFORE, (AFUNPTR)HookLdrGetProcedureAddress,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_END);
            RTN_Close(targetRtn);
        }
        targetRtn = RTN_FindByName(Image, "LdrGetProcedureAddressForCaller");
        if (targetRtn.is_valid()) {
            *logging << "Hook LdrGetProcedureAddressForCaller  " << std::endl;
            RTN_Open(targetRtn);
            RTN_InsertCall(targetRtn, IPOINT_BEFORE, (AFUNPTR)HookLdrGetProcedureAddress,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_END);
            RTN_Close(targetRtn);
        }

        ntdll::LdrLoadDll pLdrLoadDll = (ntdll::LdrLoadDll)RTN_Funptr(RTN_FindByName(Image, "LdrLoadDll"));
        ntdll::LdrGetProcedureAddress pLdrGetProcedureAddress = (ntdll::LdrGetProcedureAddress)RTN_Funptr(RTN_FindByName(Image, "LdrGetProcedureAddress"));
        ntdll::RtlInitUnicodeString pRtlInitUnicodeString = (ntdll::RtlInitUnicodeString)RTN_Funptr(RTN_FindByName(Image, "RtlInitUnicodeString"));
        ntdll::RtlInitAnsiString pRtlInitAnsiString = (ntdll::RtlInitAnsiString)RTN_Funptr(RTN_FindByName(Image, "RtlInitAnsiString"));

        *logging << "LdrLoadDll @ " << std::hex << pLdrLoadDll << std::endl
            << "LdrGetProcedureAddress @ " << std::hex << pLdrGetProcedureAddress << std::endl
            << "RtlInitUnicodeString @ " << std::hex << pRtlInitUnicodeString << std::endl
            << "RtlInitAnsiString @ " << std::hex << pRtlInitAnsiString << std::endl;

#ifndef _WIN64
        gX86SwitchTo64BitMode = X86SwitchTo64BitMode();

        if (gX86SwitchTo64BitMode == 0) {
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

VOID Instruction2(INS ins, VOID* v) {
    *logging << "Instruction" << std::endl;

    for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
        *logging << "test " << util::getDllName(IMG_Name(img)) << std::endl;
    }
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