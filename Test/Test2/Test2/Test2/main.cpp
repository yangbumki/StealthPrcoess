#include <Windows.h>
#include <iostream>

//typedef TCHAR* (*GetProcName)();

int main() {
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
	return 0;
};