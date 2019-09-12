#include "stdafx.h"
#include <iostream>
#include "ShellCode.h"

using namespace std;

bool InjectThread(DWORD id, char *dll);
DWORD GetProcessID();
bool setDebugPrevilege();
bool OpenProcessAndInject(DWORD processID, char* dll);

int main()
{
	if (!setDebugPrevilege()) {
		system("pause");
		return 0;
	}
	char dll[MAX_PATH] = { 0 };
	GetFullPathName("MetinWx.dll",MAX_PATH,dll,NULL);
	for (int i = 5; i >= 0; i--) {
		printf("The File MetinWx.dll will be injected the the active window in %d Seconds\n",i);
		Sleep(1000);
		system("cls");
	}

	/*if (!InjectThread(GetProcessID(), dll))
	{
		cout << "Injection failed!\n";
		system("pause");
		exit(1);

	}*/

	if (!OpenProcessAndInject(GetProcessID(), dll))
	{
		cout << "Injection failed!\n";
		system("pause");
		exit(1);

	}
    return 0;
}

bool OpenProcessAndInject(DWORD processID, char* dll) {

	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, true, processID);
	if (Process == 0)
	{
		cout << "Process ID = " << processID << "\n";
		cout << "Fail on Getting Handle!\n" << "Last Error: ";
		cout << GetLastError() << "\n";
		return 0;
	}

	bool result = injectDLL(Process, dll);
	if (result)
		CloseHandle(Process);

	return result;

}

DWORD GetProcessID() {
	
	DWORD id;
	HWND myWindow = GetConsoleWindow();
	HWND targetWindow = GetForegroundWindow();
	while (myWindow == targetWindow) {
		targetWindow = GetActiveWindow();
	}
	char windowText[MAX_PATH];
	GetWindowText(targetWindow, windowText, MAX_PATH);
	GetWindowThreadProcessId(targetWindow, &id);
	printf("File injecting in window: %s\n", windowText);
	return id;
}


BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege,BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) {
		printf("Error on LookupPrivilegeValue\n");
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0; //SE_PRIVILEGE_ENABLED
	AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(TOKEN_PRIVILEGES),&tpPrevious,&cbPrevious);

	if (GetLastError() != ERROR_SUCCESS) {
		printf("Error Adjusting previleges, Error %d\n", GetLastError());
		return FALSE;
	}

	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(hToken,FALSE,&tpPrevious,cbPrevious,NULL,NULL);

	if (GetLastError() != ERROR_SUCCESS) {
		printf("Error Adjusting previleges, Error %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

bool setDebugPrevilege() {
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("Fail to Open Thread token Error code: %d\n", GetLastError());
		return false;
	}
	return SetPrivilege(hToken, SE_DEBUG_NAME, true);
}

bool InjectThread(DWORD id, char *dll)
{
	bool result = 1;
	if (id == 0)
		return 0;
	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, true,id);
	if (Process == 0)
	{
		cout << "Process ID = " << id << "\n";
		cout << "Fail on Getting Handle!\n" << "Last Error: ";
		cout << GetLastError() << "\n";
		return 0;
	}
	LPVOID Memory;
	LPVOID LoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"); ;
	
	Memory = (LPVOID)VirtualAllocEx(Process, NULL, strlen(dll) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(Process, (LPVOID)Memory, dll, strlen(dll) + 1, NULL);

	HANDLE hThread = CreateRemoteThread(Process, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibrary, (LPVOID)Memory, NULL, NULL);

	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);

		DWORD exitCode = 0;
		GetExitCodeThread(hThread, &exitCode);

		if (exitCode) {
			result =  1;
		}
		else {
			printf("Error Loading Library\n");
			result = 0;
		}


	}
	else {
		printf("Error Creating thread\n");
		result = 0;
	}

	CloseHandle(Process);

	VirtualFreeEx(Process, (LPVOID)Memory, 0, MEM_RELEASE);

	return result;
}
