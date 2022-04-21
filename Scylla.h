#pragma once

#include "Ntdll.h"

#define WINAPI // __stdcall

typedef const ntdll::WCHAR * (WINAPI * def_ScyllaVersionInformationW)();
typedef const char* (WINAPI* def_ScyllaVersionInformationA)();
typedef ntdll::DWORD(WINAPI* def_ScyllaVersionInformationDword)();

typedef int (WINAPI* def_ScyllaStartGui)(ntdll::DWORD dwProcessId, ntdll::HINSTANCE mod);

typedef const BOOL(WINAPI* def_ScyllaDumpCurrentProcessA)(const char* fileToDump, ntdll::DWORD_PTR imagebase, ntdll::DWORD_PTR entrypoint, const char* fileResult);
typedef const BOOL(WINAPI* def_ScyllaDumpProcessA)(ntdll::DWORD_PTR pid, const char* fileToDump, ntdll::DWORD_PTR imagebase, ntdll::DWORD_PTR entrypoint, const char* fileResult);
typedef const BOOL(WINAPI* def_ScyllaRebuildFileA)(const char* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);

typedef const BOOL(WINAPI* def_ScyllaDumpCurrentProcessW)(const ntdll::WCHAR* fileToDump, ntdll::DWORD_PTR imagebase, ntdll::DWORD_PTR entrypoint, const ntdll::WCHAR* fileResult);
typedef const BOOL(WINAPI* def_ScyllaDumpProcessW)(ntdll::DWORD_PTR pid, const ntdll::WCHAR* fileToDump, ntdll::DWORD_PTR imagebase, ntdll::DWORD_PTR entrypoint, const ntdll::WCHAR* fileResult);
typedef const BOOL(WINAPI* def_ScyllaRebuildFilew)(const ntdll::WCHAR* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);

typedef int (WINAPI* def_ScyllaIatSearch)(ntdll::DWORD dwProcessId, ntdll::DWORD_PTR* iatStart, ntdll::DWORD* iatSize, ntdll::DWORD_PTR searchStart, BOOL advancedSearch);
typedef int (WINAPI* def_ScyllaIatFixAutoW)(ntdll::DWORD_PTR iatAddr, ntdll::DWORD iatSize, ntdll::DWORD dwProcessId, const ntdll::WCHAR* dumpFile, const ntdll::WCHAR* iatFixFile);

