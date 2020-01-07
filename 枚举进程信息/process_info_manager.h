#ifndef __PROCESS_INFO_MANAGER_H__
#define __PROCESS_INFO_MANAGER_H__

#include <Windows.h>

NTSTATUS AKOpenProcess(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ HANDLE ProcessId);

NTSTATUS GetProcessImageFileNameWin32(_In_ HANDLE ProcessHandle, _Out_ PWCHAR *FileName);

NTSTATUS GetProcessImageFileNameByProcessId(_In_ HANDLE ProcessId, _Out_ PWCHAR *FileName);

PWCHAR GetFileName(_In_ PWCHAR FileName);

PWCHAR GetKernelFileName();

#endif