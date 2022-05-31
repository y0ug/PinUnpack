#include "pin.H"
#include <iostream>
#include <fstream>

#include "Ntdll.h"
#include "SyscallHook.h"
#include "Util.h"
#include "Scylla.h"


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

class UnpackCtx {
public:
	UnpackCtx() {};
	~UnpackCtx() {};

	std::string TargetModuleName;
	std::vector<IMG> TargetsImg;
	SyscallNameMap syscallMap;
	TLS_KEY syscallTlsKey;
};


std::ofstream* logging;
UnpackCtx _UnpackCtx;

typedef const ntdll::DWORD(WINAPI* def_dumperFileAlignA)(const char* filename, ntdll::BYTE* image);
typedef const ntdll::DWORD(WINAPI* def_dumperMemAligA)(const char* filename, ntdll::BYTE* image);



ntdll::LdrLoadDll g_LdrLoadDll = NULL;
ntdll::LdrGetProcedureAddress g_LdrGetProcedureAddress = NULL;
ntdll::RtlInitUnicodeString g_RtlInitUnicodeString = NULL;
ntdll::RtlInitAnsiString g_RtlInitAnsiString = NULL;
ntdll::RtlFreeUnicodeString g_RtlFreeUnicodeString = NULL;
ntdll::RtlFreeAnsiString g_RtlFreeAnsiString = NULL;

ntdll::HMODULE hDump = NULL;
def_dumperMemAligA g_dumperMemAlignA = NULL;

extern std::map<ntdll::PVOID, MEMTRACK> memtrack_lookup;


KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
	"o", "", "Specify file name for the output");
KNOB<std::string> KnobModuleName(KNOB_MODE_WRITEONCE, "pintool",
	"m", "", "Analysed module name (by default same as app name)");

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
		name = util::FileBasename(IMG_Name(img));
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
	THREADID tid,
	CONTEXT* ctx,
	SYSCALL_STANDARD std,
	void* v)
{
	PinLocker lock;
	SYSCALLTRACK *st = (SYSCALLTRACK*)PIN_GetThreadData(_UnpackCtx.syscallTlsKey, tid);
	if (st == NULL) {
		*logging << "Syscall lookup error, "
			<< std::hex << tid << " not found" << std::endl;
		return;
	}

	const char* name = _UnpackCtx.syscallMap.getName(st->syscall_number);
	if (name != NULL) {
		for (const auto& e : InterceptExit) {
			if (strcmp(name, e.szFunctionName) == 0) {
				ADDRINT ret = PIN_GetSyscallReturn(ctx, std);

				/**logging << "tid: " << tid
					<< "\tsyscall: " << st.syscall_number
					<< "\tname: " << name
					<< "\tret: " << ret
					<< std::endl;*/

				switch (e.nParam) {
				case 1:
					((FnSyscallInterceptExit)e.syscallCB)(ret, (void*)st->data);
					break;
				}
				break;
			}
		}
	}


	if (st->data != NULL) {
		delete st->data;
	}

	//syscall_lookup.erase(tid);
	delete st;
	PIN_SetThreadData(_UnpackCtx.syscallTlsKey, NULL, tid);
}

void SyscallEntry(
	THREADID tid,
	CONTEXT* ctx,
	SYSCALL_STANDARD std,
	void* v)
{
	PinLocker lock;

	UINT32  syscall_number = PIN_GetSyscallNumber(ctx, std);

	SYSCALLTRACK *st = new SYSCALLTRACK{syscall_number, NULL};

	const char* name = _UnpackCtx.syscallMap.getName(syscall_number);
	if (name != NULL) {
		for (const auto& e : InterceptEntry) {
			if (strcmp(name, e.szFunctionName) == 0) {
				void* args[12];
				for (int j = 0; j < e.nParam; j++) {
					args[j] = (void*)PIN_GetSyscallArgument(ctx, std, j);
				}

				switch (e.nParam) {
				case 4:
					st->data = ((FnSyscallIntercept4)e.syscallCB)(args[0], args[1], args[2], args[3]);
					break;
				case 5:
					st->data = ((FnSyscallIntercept6)e.syscallCB)(args[0], args[1], args[2], args[3], args[4], args[5]);
					break;
				case 6:
					st->data = ((FnSyscallIntercept6)e.syscallCB)(args[0], args[1], args[2], args[3], args[4], args[5]);
					break;
				case 8:
					st->data = ((FnSyscallIntercept8)e.syscallCB)(args[0], args[1], args[2], args[3], args[4], args[5],
						args[6], args[7]);
				case 11:
					st->data = ((FnSyscallIntercept11)e.syscallCB)(args[0], args[1], args[2], args[3], args[4], args[5],
						args[6], args[7], args[8], args[9], args[10]);
					break;
				}
				break;
			}
		}
	}

	PIN_SetThreadData(_UnpackCtx.syscallTlsKey, (void*)st, tid);

	/*
	if (syscall_lookup.count(tid) != NULL) {
		*logging << "orphelan syscall lookup" << std::endl;
		if (syscall_lookup[tid].data != NULL) {
			delete syscall_lookup[tid].data;
		}

		syscall_lookup.erase(tid);
	}
	syscall_lookup[tid] = st;
	*/
}



void SetupHookNtdll(IMG Image)
{
	_UnpackCtx.syscallMap.load((ntdll::HMODULE)IMG_StartAddress(Image));

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

	g_LdrLoadDll = (ntdll::LdrLoadDll)RTN_Funptr(RTN_FindByName(Image, "LdrLoadDll"));
	g_LdrGetProcedureAddress = (ntdll::LdrGetProcedureAddress)RTN_Funptr(RTN_FindByName(Image, "LdrGetProcedureAddress"));
	g_RtlInitUnicodeString = (ntdll::RtlInitUnicodeString)RTN_Funptr(RTN_FindByName(Image, "RtlInitUnicodeString"));
	g_RtlInitAnsiString = (ntdll::RtlInitAnsiString)RTN_Funptr(RTN_FindByName(Image, "RtlInitAnsiString"));
	g_RtlFreeUnicodeString = (ntdll::RtlFreeUnicodeString)RTN_Funptr(RTN_FindByName(Image, "RtlFreeUnicodeString"));
	g_RtlFreeAnsiString = (ntdll::RtlFreeAnsiString)RTN_Funptr(RTN_FindByName(Image, "RtlFreeAnsiString"));

	ntdll::UNICODE_STRING dn;
#ifdef _WIN64
	g_pRtlInitUnicodeString(&dn, L"Dumper_x64.dll");
#else
	g_RtlInitUnicodeString(&dn, L"Dumper_x86.dll");
	//const ntdll::UNICODE_STRING dn = RTL_CONSTANT_STRING(L"Dumper_x86.dll");
#endif
	g_LdrLoadDll(NULL, NULL, &dn, &hDump);

	ntdll::ANSI_STRING fn;
	g_RtlInitAnsiString(&fn, "dumperMemAlignA");
	g_LdrGetProcedureAddress(hDump, &fn, 0, (ntdll::PVOID*)&g_dumperMemAlignA);


#ifndef _WIN64
	gX86SwitchTo64BitMode = X86SwitchTo64BitMode();

	if (gX86SwitchTo64BitMode == 0) {

		/**logging << "LdrLoadDll @ " << std::hex << pLdrLoadDll << std::endl
			<< "LdrGetProcedureAddress @ " << std::hex << pLdrGetProcedureAddress << std::endl
			<< "RtlInitUnicodeString @ " << std::hex << pRtlInitUnicodeString << std::endl
			<< "RtlInitAnsiString @ " << std::hex << pRtlInitAnsiString << std::endl;*/

		ntdll::ANSI_STRING fn;
		g_RtlInitAnsiString(&fn, "Wow64Transition");

		void* pWow64Transition = 0;
		pWow64Transition = (void*)RTN_Funptr(RTN_FindByName(Image, "Wow64Transition"));
		g_LdrGetProcedureAddress((VOID*)IMG_StartAddress(Image), &fn, 0, &pWow64Transition);

		if (pWow64Transition != 0) {
			gX86SwitchTo64BitMode = *(ADDRINT*)pWow64Transition;
		}

		*logging << "Wow64Transition @" << std::hex << pWow64Transition << std::endl;
	}

	*logging << "X86SwitchTo64BitMode @" << std::hex << gX86SwitchTo64BitMode << std::endl;
#endif
}



/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID Transitions(
	const CONTEXT* ctx, 
	const THREADID tid, 
	const ADDRINT prevVA, 
	const ADDRINT Address, 
	BOOL isIndirect)
{
	PinLocker locker;

	IMG callerModule = IMG_FindByAddress(prevVA);
	IMG targetModule = IMG_FindByAddress(Address);

	if (callerModule == targetModule) {
		return;
	}

	bool isCallerPeModule = IMG_Valid(callerModule);
	bool isTargetPeModule = IMG_Valid(targetModule);

	std::string callerName = hexstr(prevVA);
	std::string targetName = hexstr(Address);

	if (isCallerPeModule) {
		callerName = util::FileBasename(IMG_Name(callerModule));
	}

	if (isTargetPeModule) {
		targetName = util::FileBasename(IMG_Name(targetModule));
	}

	if (gX86SwitchTo64BitMode && gX86SwitchTo64BitMode == Address) {
		isTargetPeModule = true;
	}

	for (const auto& e : _UnpackCtx.TargetsImg) {
		if (e == callerModule) {
			std::string targetFnName = RTN_FindNameByAddress(Address);
			ADDRINT rva = prevVA -  IMG_LoadOffset(callerModule);
			*logging << callerName << "::" << rva << " -> " << targetName << "::" << targetFnName << std::endl;
			break;
		}
	}

	if (!isCallerPeModule && isTargetPeModule) {
		std::string targetFnName = RTN_FindNameByAddress(Address);
		*logging << callerName << " -> " << targetName << "::" << targetFnName << std::endl;
	}
	for ( auto& e : memtrack_lookup) {
		if ((ADDRINT)e.second.BaseAddress <= Address && \
			Address <= (ADDRINT)e.second.BaseAddress+e.second.RegionSize) 
		{
			if (!e.second.isDump){
				*logging << "DUMP ME!!" << std::endl;
				e.second.isDump = true;
				std::string filename = "dump_" + hexstr(e.second.BaseAddress) ;
				std::ofstream fs((filename + ".dmp").c_str(), std::ios::binary);
				//fs.write((char*)e.second.BaseAddress, e.second.RegionSize);
				//fs.close();

				g_dumperMemAlignA((filename + ".bin").c_str(), (ntdll::BYTE*)e.second.BaseAddress);
			}
			break;
		}
	}

	if (isCallerPeModule && !isTargetPeModule) {
		std::string targetFnName = RTN_FindNameByAddress(Address);

		/*MemRange range = MemPageRange(Address);

		ntdll::ULONGLONG eopRVA = (ntdll::ULONGLONG)(Address - (ADDRINT)range.Base());
		ntdll::ULONGLONG eopVA = (ntdll::ULONGLONG)(Address);
		ntdll::ULONGLONG base = (ntdll::ULONGLONG)range.Base();
		ntdll::ULONGLONG len = (ntdll::ULONGLONG)range.End() - base;*/
	}
}


VOID Instruction(INS ins, VOID* v)
{
	//if ((INS_IsControlFlow(ins) || INS_IsFarJump(ins))) {
	if (INS_IsIndirectControlFlow(ins) || INS_IsFarJump(ins)) {
		BOOL isIndirect = INS_IsIndirectControlFlow(ins) && !INS_IsRet(ins);
		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)Transitions,
			IARG_CONTEXT,
			IARG_THREAD_ID,
			IARG_INST_PTR,
			IARG_BRANCH_TARGET_ADDR,
			IARG_BOOL, isIndirect,
			IARG_END
		);
	}
}


VOID ImageLoad(IMG img, VOID* v)
{
	PinLocker locker;

	const std::string dllName = util::FileBasename(IMG_Name(img));;

	*logging << dllName << " @ " << std::hex << IMG_LoadOffset(img) << std::endl;

	if (dllName.compare("ntdll.dll") == 0) {
		SetupHookNtdll(img);
	}

	if (_UnpackCtx.TargetModuleName.compare(dllName) == 0) {
		_UnpackCtx.TargetsImg.push_back(img);
	}
}


int main(int argc, char* argv[])
{
	PIN_InitSymbols();

	if (PIN_Init(argc, argv))
	{
		return Usage();
	}

	_UnpackCtx.TargetModuleName = util::FileBasename(KnobModuleName.Value());
	if (_UnpackCtx.TargetModuleName.length() == 0) {
		for (int i = 1; i < (argc - 1); i++) {
			if (strcmp(argv[i], "--") == 0) {
				_UnpackCtx.TargetModuleName = util::FileBasename(argv[i + 1]);
				break;
			}
		}
	}

	IMG_AddInstrumentFunction(ImageLoad, NULL);
	INS_AddInstrumentFunction(Instruction, NULL);

	_UnpackCtx.syscallTlsKey = PIN_CreateThreadDataKey(NULL);

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