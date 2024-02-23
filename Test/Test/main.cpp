#include <Windows.h>
#include <iostream>
#include <conio.h>

typedef void (*SetProcName)(const TCHAR* name);
typedef TCHAR* (*GetProcName)();

typedef NTSTATUS(*NewQsi)(_In_ BYTE SYSTEM_INFORMATION_CLASS, _In_ _Out_ void*, _In_ ULONG sysInfoLen, _Out_ ULONG* retLen);

void SharedTestDLL();

int main() {
	HMODULE ntdllHandle = GetModuleHandleA("ntdll.dll");
	DWORD oldProtect = NULL;
	void* zwQsiHandle = NULL;

	if (ntdllHandle == NULL) {
		printf_s("GetModuleHandleA");
		exit(1);
	};
		
	zwQsiHandle = GetProcAddress(ntdllHandle, "ZwQuerySystemInformation");
	if (zwQsiHandle == NULL) {
		printf_s("GetProcAddress");
		exit(1);
	};
		
	auto result = VirtualProtect(zwQsiHandle, 8, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!result) {
		printf_s("VirtualProtect");
		exit(1);
	};

	

	while (1) {
		if (_kbhit()) break;
	};

	return 0;
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