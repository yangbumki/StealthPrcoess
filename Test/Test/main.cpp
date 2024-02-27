#include <Windows.h>
#include <iostream>
#include <conio.h>
#include <TlHelp32.h>

#define JMP_COMMAND_PADDING				6
#define SYSTEM_PROCESS_INFORMATION		0x05
#define STATUS_SEVERITY_SUCCESS			0x0

typedef void (*SetProcName)(const TCHAR* name);
typedef TCHAR* (*GetProcName)();
typedef BYTE	SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(*NewQsi)(_In_ BYTE SYSTEM_INFORMATION_CLASS, _In_ _Out_ void* sysInfo, _In_ ULONG sysInfoLen, _Out_ ULONG* retLen);


void ErrorMessage(const char* str) {
	MessageBoxA(NULL, str, "ERROR", NULL);
	exit(1);
};

void SharedTestDLL();
void EXENameParsing();
NTSTATUS NewQuerySystemInformation(_In_ BYTE SYSTEM_INFORMATION_CLASS, _In_ _Out_ void* sysInfo, _In_ ULONG sysInfoLen, _Out_ ULONG* retLen);
void Hooking(const char* dllName, const char* srcProc, const void* buffer, int bufferSize);

void* zwQsiHandle = NULL;
BYTE* oriBuffer = nullptr, *buffer = nullptr;
int oriSize = 0, bufferSize = 0;
const wchar_t* HIDE_PROCESS_NAME = L"Test.exe";

int main() {
	HMODULE ntdllHandle = GetModuleHandleA("ntdll.dll");
	DWORD oldProtect = NULL;

	if (ntdllHandle == NULL) {
		printf_s("GetModuleHandleA");
		exit(1);
	};
		
	zwQsiHandle = GetProcAddress(ntdllHandle, "ZwQuerySystemInformation");
	if (zwQsiHandle == NULL) {
		printf_s("GetProcAddress");
		exit(1);
	};
		
	/*auto result = VirtualProtect(zwQsiHandle, 8, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!result) {
		printf_s("VirtualProtect");
		exit(1);
	};*/

	//// 어셈블리어는 명령어 해석할 때 6바이트 씩 읽는 거 같고, 64비트 메모리는 8바이트 씩 끊는다.
	//BYTE jmpBuffer[6] = { 0xFF, 0x25, 0, };
	//BYTE buffer[16] = {0,};

	//printf_s("%p \n", NewQuerySystemInformation);

	//DWORD64 tempAddr = (DWORD64)NewQuerySystemInformation;

	//memcpy(&buffer[0], jmpBuffer, 6);
	//memcpy(&buffer[6], &tempAddr, 6);
	////printf_s("pBuf : %x \n", buffer);



	//memcpy(oriBuffer, &zwQsiHandle, sizeof(oriBuffer));
	//memcpy(zwQsiHandle, buffer, sizeof(buffer));

	BYTE jmpCode[JMP_COMMAND_PADDING] = { 0xff, 0x25, 0, };
	DWORD64 offsetAddr = (DWORD64)NewQuerySystemInformation;
	int totalSize = bufferSize =   JMP_COMMAND_PADDING + sizeof(offsetAddr);
	buffer = new BYTE[totalSize];
	memcpy_s(buffer,JMP_COMMAND_PADDING, jmpCode, JMP_COMMAND_PADDING);
	memcpy_s(&buffer[JMP_COMMAND_PADDING], sizeof(DWORD64), &offsetAddr, sizeof(DWORD64));

	

	while (1) {
		Hooking("ntdll.dll", "NtQuerySystemInformation", buffer, totalSize);
		CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
		if (_kbhit()) break;
	};
	
	return 0;
};

void Hooking(const char* dllName, const char* srcProc, const void* buffer, int bufferSize) {
	HMODULE dll = GetModuleHandleA(dllName);
	if (dll == NULL) ErrorMessage("dll");

	void* proc = GetProcAddress(dll, srcProc);
	if (proc == NULL) ErrorMessage("proc");

	/*BYTE jmpCode[JMP_COMMAND_PADDING] = { 0xFF, 0x25, 0, };
	DWORD64 newProcAddr = 0;
	DWORD64 offsetAddr = 0;*/
	
	//int tmpSize = 0;
	DWORD oldProtect;

	//auto result = VirtualProtect(proc, sizeof(jmpCode) + sizeof(newProcAddr), PAGE_EXECUTE_READWRITE, &oldProtect);
	auto result = VirtualProtect(proc, bufferSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!result) ErrorMessage("VirtualProtect");

	if (oriBuffer == nullptr) {
		oriBuffer = new BYTE[bufferSize];
		memcpy_s(oriBuffer, bufferSize, proc, bufferSize);
		oriSize = bufferSize;
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
		byte Reserved1[48];
		PVOID Reserved2[3];
		HANDLE UniqueProcessID;
		PVOID Reserved3;
		ULONG HandleCount;
		byte Reserved4[4];
		PVOID Reserved5[11];
		SIZE_T PeekPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER Reserved6[6];
	}SystemProcessInforMation, *PSystemPrcoessInforMation;

	NTSTATUS status;
	FARPROC pFunc;
	PSystemPrcoessInforMation pCur = NULL, pPrev = NULL;
	char procName[MAX_PATH] = { 0, };
	int result;

	Hooking("ntdll.dll", "NtQuerySystemInformation", oriBuffer, oriSize);
	status = ((NewQsi)zwQsiHandle) (sysInfoClass, sysInfo, sysInfoLen, retLen);
	if (status != STATUS_SEVERITY_SUCCESS) goto __NEWQSI_END;

	if (sysInfoClass == SYSTEM_PROCESS_INFORMATION) {
		pCur = (PSystemPrcoessInforMation)sysInfo;

		while (TRUE) {
			if (pCur->Reserved2[1] != NULL) {
				result = _wcsicmp((PWSTR)(pCur->Reserved2[1]), HIDE_PROCESS_NAME);
				if (result == 0) {
					if (pCur->NextEntryOffset == 0)
						pPrev->NextEntryOffset = 0;
					else
						pPrev->NextEntryOffset += pCur->NextEntryOffset;
				}else
					pPrev = pCur;
			};
			if (pCur->NextEntryOffset == 0)
				break;

			pCur = (PSystemPrcoessInforMation)((ULONG64)pCur + pCur->NextEntryOffset);
		};
	};

	__NEWQSI_END:
	Hooking("ntdll.dll", "ZwQuerySystemInformation", buffer, bufferSize);
	return status;
};

void SharedTestDLL() {
	auto testDLLHandle = LoadLibrary(L"D:\\Source\\StealthProcess\\Test\\Test.dll");
	if (testDLLHandle == NULL) {
		printf_s("DLL load Error\n");
		exit(1);
	};

	auto setProcName = GetProcAddress(testDLLHandle, "SetProcName");
	if (setProcName == NULL) {
		printf_s("Function load Error\n");
		exit(1);
	};

	auto getProcName = GetProcAddress(testDLLHandle, "GetProcName");
	if (testDLLHandle == NULL) {
		printf_s("Function load Error\n");
		exit(1);
	};

	const TCHAR* sharedName = L"Hello";

	(SetProcName(setProcName))(sharedName);
	wprintf_s(L"After SharedName : %s \n", (GetProcName(getProcName))());
};

void EXENameParsing() {
	char fileName[MAX_PATH] = { 0, };
	auto result = GetModuleFileNameA(NULL, fileName, MAX_PATH);
	if (result < 0) {
		printf_s("GetModuleFileNameA()");
		exit(1);
	};

	printf_s("GetModuleFileName Result : %d \n", result);
	printf_s("File Name : %s \n", fileName);

	char* exeName = strrchr(fileName, '\\');
	exeName = exeName + 1;

	printf_s("EXE name : %s \n", exeName);
};