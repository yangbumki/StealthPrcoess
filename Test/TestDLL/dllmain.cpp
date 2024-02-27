// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"

#pragma comment(linker, "/SECTION:.SHARE,RWS")
#pragma data_seg(".SHARE")
TCHAR g_szProcName[MAX_PATH] = { 0, };
#pragma data_seg()

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved    
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "TEST", "TEST.DLL", NULL);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

#ifdef __cplusplus
extern "C" {
#endif
    __declspec(dllexport) void SetProcName(LPCTSTR szProcName) {
        wcscpy_s(g_szProcName, szProcName);
    };

    __declspec(dllexport) TCHAR* GetProcName() {
        return g_szProcName;
    };
#ifdef __cplusplus
};
#endif