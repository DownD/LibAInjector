#include "stdafx.h"
#include <iostream>

using namespace std;

bool InjectThread(DWORD *id, char *dll);
void GetProcessID(DWORD *id);

int main()
{
	char dll[MAX_PATH];
	DWORD id = 0;
	GetProcessID(&id);
	if (id == 0)
	{
		cout << "Injection failed!  ID = 0\n";
		Sleep(3000);
		exit(1);
	}

	GetFullPathName("DownInternal.dll",MAX_PATH,dll,NULL);
	if (!InjectThread(&id, dll))
	{
		cout << "Injection failed!\n";
		Sleep(3000);
		exit(1);

	}
	else
	exit(1);
    return 0;
}

void GetProcessID(DWORD *id) {
	GetWindowThreadProcessId(FindWindow(NULL, "Lethal War - Legends Never Die! - 1.6.0.7"), id);
	return;
}

bool InjectThread(DWORD *id, char *dll)
{
	if (*id == 0)
		return 0;
	HANDLE Process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, *id);
	if (Process == 0)
	{
		cout << "Process ID = " << *id << "\n";
		cout << "Fail on Getting Handle!\n" << "Last Error: ";
		cout << GetLastError() << "\n";
		return 0;
	}
	LPVOID Memory;
	LPVOID LoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"); ;
	
	Memory = (LPVOID)VirtualAllocEx(Process, NULL, strlen(dll) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(Process, (LPVOID)Memory, dll, strlen(dll) + 1, NULL);

	CreateRemoteThread(Process, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibrary, (LPVOID)Memory, NULL, NULL);

	CloseHandle(Process);

	VirtualFreeEx(Process, (LPVOID)Memory, 0, MEM_RELEASE);
	
	return 1;
}
