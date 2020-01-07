#ifndef __PROCESS_INFO_H__
#define __PROCESS_INFO_H__

#include <Windows.h>
#include <string>
#include <vector>

typedef struct _ak_process_info {
	DWORD pid; // process id
	DWORD ppid; // parent process id

	std::wstring processName;
	std::wstring processLocation;

	DWORD queryHandle;

	// Flags
	UINT isHandleValid; // 1
	UINT isWow64; // 1
	UINT isWow64Valid; // 1
	UINT isProtectedProcess; // 1
	UINT isSecureProcess; // 1
	UINT isSubsystemProcess; // 1
} ak_process_info;

VOID InitialDevice();
std::vector<ak_process_info> enum_process_info();
std::vector<ak_process_info> enum_process_info_with_nt_query();

#endif
