#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    __declspec(dllexport) DWORD dumperFileAlignA(const char* filename, BYTE* image);
    __declspec(dllexport) DWORD dumperMemAlignA(const char* filename, BYTE* image);

#ifdef __cplusplus
}
#endif


