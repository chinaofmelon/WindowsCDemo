#include "crash_collection_server.h"
#include <stdio.h>

typedef BOOL(*MiniDumpWriteDumpFun)(HANDLE, DWORD, HANDLE, DWORD, VOID*, VOID*, VOID*);

int crash_collection_server(DWORD PID) {
	HANDLE hProc = NULL;
	HANDLE hFile = NULL;
	BOOL bSuccess = FALSE;
	MiniDumpWriteDumpFun MiniDumpWriteDump;

	MiniDumpWriteDump = (MiniDumpWriteDumpFun)GetProcAddress(LoadLibrary(L"Dbghelp.dll"), "MiniDumpWriteDump");
	printf("MiniDumpWriteDump found at 0x%p\n", MiniDumpWriteDump);

	if (MiniDumpWriteDump == NULL) {
		printf("Can't resolve MiniDumpWriteDump. Exiting (%ld)\n", GetLastError());
		ExitProcess(0);
	}

	printf("Trying to dump PID: %d\n", PID);
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);
	printf("Process HANDLE 0x%p\n", hProc);

	if (hProc == NULL) {
		printf("HANDLE is NULL. Exiting (%ld)\n", GetLastError());
		ExitProcess(0);
	}

	hFile = CreateFile(L"memory.dmp", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("memory.dmp HANDLE 0x%p\n", hFile);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Can't create memory.dmp. Exiting (%ld)\n", GetLastError());
		CloseHandle(hProc);
		ExitProcess(0);
	}

	bSuccess = MiniDumpWriteDump(hProc, PID, hFile, 2, NULL, NULL, NULL);
	printf("Process Completed (%d)(%ld)", (DWORD)bSuccess, GetLastError());

	CloseHandle(hProc);
	CloseHandle(hFile);
	return 0;
}