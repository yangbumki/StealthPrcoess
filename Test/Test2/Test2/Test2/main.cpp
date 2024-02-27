#include <Windows.h>
#include <iostream>

//typedef TCHAR* (*GetProcName)();

void ErrorMessage(const char* msg) {
	MessageBoxA(NULL, msg, "ERROR", NULL);
	ExitProcess(1);
};

void test() {
};

void Hooking(const char* dllName, const char* srcProc,const void* dstProc);

int main() {

	Hooking("ntdll.dll", "NtQuerySystemInformation", test);
	return 0;
};

void Hooking(const char* dllName, const char* srcProc, const void* dstProc) {
	HMODULE dll = GetModuleHandleA(dllName);
	if (dll == NULL) ErrorMessage("dll");

	void* proc = GetProcAddress(dll, srcProc);
	if (proc == NULL) ErrorMessage("proc");

	BYTE jmpCode[6] = { 0xFF, 0x25, 0, };
	DWORD64 newProcAddr = 0;
	DWORD64 offsetAddr = 0;
	int tmpSize = 0;
	DWORD oldProtect;

	auto result = VirtualProtect(proc, sizeof(jmpCode) + sizeof(newProcAddr), PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!result) ErrorMessage("VirtualProtect");

	tmpSize = sizeof(jmpCode);
	result = memcpy_s(proc, tmpSize, jmpCode, tmpSize);
	if (result != 0) ErrorMessage("memcpy_s");

	offsetAddr = ((DWORD64)proc + tmpSize);
	newProcAddr = (DWORD64)dstProc;
	tmpSize = sizeof(newProcAddr);
	result = memcpy_s((void*)offsetAddr, tmpSize, &newProcAddr, tmpSize);

	result = VirtualProtect(proc, sizeof(jmpCode) + sizeof(newProcAddr), oldProtect, &oldProtect);
	if (!result) ErrorMessage("VirtualProtect");
};

void TestSharedDLL() {
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

	wprintf_s(L"ShareName : %s \n", getProcName());
};