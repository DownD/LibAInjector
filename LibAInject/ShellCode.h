#pragma once
#include "stdafx.h"

#define ERROR_SETTING_PATH 0x1
#define ERROR_LOADING_DLL 0x2


typedef BOOL(__stdcall *_SetDllDirectoryA)(LPCSTR path);
typedef BOOL(__stdcall *_LoadLibraryA)(LPCSTR file);

struct Memory{
	_SetDllDirectoryA fSetDllDirectory;
	_LoadLibraryA fLoadLibraryA;

	char directory[MAX_PATH];
	char fileName[MAX_PATH];
};

#pragma optimize( "", off )

static int _stdcall shellCode32(Memory* mem){

	if (!mem->fSetDllDirectory(mem->directory)) {
		return ERROR_SETTING_PATH;
	}
	if (!mem->fLoadLibraryA(mem->fileName)) {
		return ERROR_LOADING_DLL;
	}

	int i = 0;
	return 1;

	return 0;
}

static int endFunction(){ return 0; };
#pragma optimize("", on )


//BUFFER OVERFLOW POSSIBLE
bool splitFullPath(char* fullPath, char * pathBuffer, char* nameBuffer) {
	int fullPathSize = strlen(fullPath)-1;

	if (!fullPathSize) {
		printf("Path is Empty\n");
		return false;
	}
	int counter = 1;
	for (int i = fullPathSize - 1; i >= 0; i--, counter++) {
		if (fullPath[i] == '/' || fullPath[i] == '\\') {
			memcpy(nameBuffer, &fullPath[i + 1], counter);
			nameBuffer[counter] = 0;
			memcpy(pathBuffer, fullPath, i+1);
			pathBuffer[i+1] = 0;
			return true;
		}
	}
	printf("Is not Path\n");
	return false;
	
}

bool injectDLL(HANDLE process,char* fullPath){

	Memory mem = { 0 };

	HMODULE kernel32Handle = GetModuleHandle("kernel32.dll");
	if (!kernel32Handle) {
		printf("Fail getting Kernel Handle\n");
		return false;
	}
	mem.fLoadLibraryA = (_LoadLibraryA)GetProcAddress(kernel32Handle, "LoadLibraryA");
	mem.fSetDllDirectory = (_SetDllDirectoryA)GetProcAddress(kernel32Handle, "SetDllDirectoryA");

	splitFullPath(fullPath, mem.directory, mem.fileName);

	if (!mem.fLoadLibraryA) {
		printf("Faill getting LoadLibraryA from Kernel32.dll\n");
		return false;
	}

	if (!mem.fSetDllDirectory) {
		printf("Faill getting SetDllDirectory from Kernel32.dll\n");
		return false;
	}


	void* memAlloc = VirtualAllocEx(process, NULL, sizeof(Memory), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!memAlloc) {
		printf("Fail To allocate Memory, Error: %d\n", GetLastError());
		return false;
	}

	SIZE_T numBytes = 0;
	if (!WriteProcessMemory(process, memAlloc, &mem, sizeof(Memory), &numBytes) || numBytes != sizeof(Memory)) {
		printf("Fail To Write Memory, Error: %d\n", GetLastError());
		VirtualFreeEx(process, (LPVOID)memAlloc, 0, MEM_RELEASE);
		return false;
	}

	int functionSize = (int)&endFunction - (int)&shellCode32;

	printf("ShellFunction Size = %d\n", functionSize);

	void* functionAlloc = VirtualAllocEx(process, NULL, functionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!functionAlloc) {
		printf("Fail To allocate Memory, Error: %d\n", GetLastError());
		VirtualFreeEx(process, (LPVOID)memAlloc, 0, MEM_RELEASE);
		return false;
	}

	numBytes = 0;
	if (!WriteProcessMemory(process, functionAlloc, &shellCode32, functionSize, &numBytes) || numBytes != functionSize) {
		printf("Fail To Write Memory, Error: %d\n", GetLastError());
		VirtualFreeEx(process, (LPVOID)functionAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(process, (LPVOID)memAlloc, 0, MEM_RELEASE);
		return false;
	}

	/*printf("Path = %s\n", mem.directory);
	printf("FileName = %s\n", mem.fileName);
	printf("ShellCode = %#x\n", &shellCode32);
	printf("Memory Shellcode = %#x || Function ShellCode = %#x\n", memAlloc, functionAlloc);
	system("pause");*/

	HANDLE hThread = CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)functionAlloc, (LPVOID)memAlloc, NULL, NULL);
	if (!hThread) {
		printf("Fail Creating Thread, Error: %d\n", GetLastError());
		VirtualFreeEx(process, (LPVOID)functionAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(process, (LPVOID)memAlloc, 0, MEM_RELEASE);
	}

	DWORD state = WaitForSingleObject(hThread, INFINITE);

	if (state == WAIT_TIMEOUT || state == WAIT_FAILED) {
		printf("Thread Timeout Reached or WaiForSingleObject failed: GetLastError = %d\n", GetLastError());
		CloseHandle(hThread);
		VirtualFreeEx(process, (LPVOID)functionAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(process, (LPVOID)memAlloc, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);
	VirtualFreeEx(process, (LPVOID)memAlloc, 0, MEM_RELEASE);
	return true;
}