#include "process_info.h"
#include <TlHelp32.h>
#include <iostream>
#include <algorithm>
#include <vector>
#include "session_manager.h"
#include "process_info_manager.h"
#include "process_private.h"
#include <ntstatus.h>
#include "string_utils.h"

#define SYSTEM_IDLE_PROCESS_ID (0) /** The PID of the idle process. */
#define SYSTEM_PROCESS_ID (4) /** The PID of the system process. */

#define SYSTEM_IDLE_PROCESS_NAME L"System Idle Process"

#define IS_REAL_PROCESS_ID(ProcessId) ((LONG_PTR)(ProcessId) > 0)

#define MAX_INFO_BUF_LEN             0x500000

std::vector<ak_process_info> enum_process_info() {
	std::vector<ak_process_info> list;

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	// 获得系统进程快照的句柄
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to enum process. Because INVALID_HANDLE_VALUE\n";
		return list;
	}
	DWORD current_session_id = actived_session_id();

	// 首先获得第一个进程
	BOOL bProcess = Process32First(hProcessSnap, &pe32);
	// 循环获得所有进程
	while (bProcess) {
		DWORD sessionId = 0;
		ProcessIdToSessionId(pe32.th32ProcessID, &sessionId);
		// 过滤非当前用户的 process
		if (sessionId != current_session_id) {
			bProcess = Process32Next(hProcessSnap, &pe32);
			continue;
		}

		ak_process_info info;

		info.pid = pe32.th32ProcessID;
		info.ppid = pe32.th32ParentProcessID;

		if (info.pid != 0) {
			info.processName = pe32.szExeFile;
		}
		else {
			info.processName = SYSTEM_IDLE_PROCESS_NAME;
		}
		std::transform(info.processName.begin(), info.processName.end(), info.processName.begin(), ::tolower);

		// Process Handle
		if (IS_REAL_PROCESS_ID(info.pid)) {
			HANDLE queryHandle;
			if (NT_SUCCESS(AKOpenProcess(&queryHandle, PROCESS_QUERY_INFORMATION, (HANDLE)info.pid))) {
				info.isHandleValid = TRUE;
			}

			if (!queryHandle) {
				AKOpenProcess(&queryHandle, PROCESS_QUERY_LIMITED_INFORMATION, (HANDLE)info.pid);
			}
			info.queryHandle = (DWORD)queryHandle;
		}

		// Process Flags
		if (info.queryHandle) {
			PROCESS_EXTENDED_BASIC_INFORMATION basicInfo;
			basicInfo.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);

			if (NT_SUCCESS(NtQueryInformationProcess((HANDLE)info.queryHandle, ProcessBasicInformation, &basicInfo, sizeof(PROCESS_EXTENDED_BASIC_INFORMATION), nullptr))) {
				info.isProtectedProcess = basicInfo.IsProtectedProcess;
				info.isSecureProcess = basicInfo.IsSecureProcess;
				info.isSubsystemProcess = basicInfo.IsSubsystemProcess;
				info.isWow64 = basicInfo.IsWow64Process;
				info.isWow64Valid = TRUE;
			}
		}

		// Process Image 
		{
			// If we're dealing with System (PID 4), we need to get the kernel file name. Otherwise, get the image file name.

			PCHAR processLocation = nullptr;
			if (info.pid != SYSTEM_PROCESS_ID) {
				if (info.queryHandle && !info.isSubsystemProcess) {
					PWCHAR tmp = nullptr;
					GetProcessImageFileNameWin32((HANDLE)info.queryHandle, &tmp);

					if (tmp) {
						info.processLocation = tmp;
						free(tmp);
					} else {
						info.processLocation = L"";
					}
				} else {
					PWCHAR fileName;
					if (NT_SUCCESS(GetProcessImageFileNameByProcessId((HANDLE)info.pid, &fileName))) {
						PWCHAR tmp = GetFileName(fileName);

						if (fileName) {
							free(fileName);
						}

						if (tmp) {
							info.processLocation = tmp;
							free(tmp);
						} else {
							info.processLocation = L"";
						}
					}
				}
			} else {
				PWCHAR fileName = GetKernelFileName();

				if (fileName) {
					PWCHAR tmp = GetFileName(fileName);

					free(fileName);

					if (tmp) {
						info.processLocation = tmp;
						free(tmp);
					} else {
						info.processLocation = L"";
					}
				}
			}
			free(processLocation);
		}
		list.push_back(info);

		bProcess = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return list;
}

std::vector<ak_process_info> enum_process_info_with_nt_query() {
	std::vector<ak_process_info> list;

	PSYSTEM_PROCESSES pSystemProc;
	DWORD dwNumberBytes = MAX_INFO_BUF_LEN, dwTotalProcess = 0, dwReturnLength = 0;
	NTSTATUS status;

	LPVOID lpSystemInfo = (LPVOID)malloc(dwNumberBytes);
	memset(lpSystemInfo, 0, dwNumberBytes);

	status = NtQuerySystemInformation(SystemProcessInformation/*NT_PROCESSTHREAD_INFO*/, lpSystemInfo, dwNumberBytes, &dwReturnLength);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		std::cout << "Failed to enum process. Because STATUS_INFO_LENGTH_MISMATCH\n";
	} else if (status != STATUS_SUCCESS) {
		std::cout << "Failed to enum process. Because NtQuerySystemInformation failed. Error is" << GetLastError() << "\n";
	} else {
		pSystemProc = (PSYSTEM_PROCESSES)lpSystemInfo;

		while (pSystemProc->NextEntryDelta != 0) {
			ak_process_info info;
			info.pid = reinterpret_cast<DWORD>(pSystemProc->ProcessId);
			info.ppid = reinterpret_cast<DWORD>(pSystemProc->InheritedFromProcessId);

			if (pSystemProc->ProcessId != 0) {
				PWCHAR name = copyString(pSystemProc->ProcessName.Buffer);
				info.processName = name;
				free(name);
			} else {
				PWCHAR name = copyString((PWCHAR)SYSTEM_IDLE_PROCESS_NAME);
				info.processName = name;
				free(name);
			}

			// Process Handle
			if (IS_REAL_PROCESS_ID(info.pid)) {
				HANDLE queryHandle = nullptr;
				if (NT_SUCCESS(AKOpenProcess(&queryHandle, PROCESS_QUERY_INFORMATION, reinterpret_cast<HANDLE>(info.pid)))) {
					info.isHandleValid = TRUE;
				}

				if (!queryHandle) {
					AKOpenProcess(&queryHandle, PROCESS_QUERY_LIMITED_INFORMATION, reinterpret_cast<HANDLE>(info.pid));
				}
				info.queryHandle = reinterpret_cast<DWORD>(queryHandle);
			}

			// Process Flags
			if (info.queryHandle) {
				PROCESS_EXTENDED_BASIC_INFORMATION basicInfo;
				basicInfo.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);

				if (NT_SUCCESS(NtQueryInformationProcess((HANDLE)info.queryHandle, ProcessBasicInformation, &basicInfo, sizeof(PROCESS_EXTENDED_BASIC_INFORMATION), nullptr))) {
					info.isProtectedProcess = basicInfo.IsProtectedProcess;
					info.isSecureProcess = basicInfo.IsSecureProcess;
					info.isSubsystemProcess = basicInfo.IsSubsystemProcess;
					info.isWow64 = basicInfo.IsWow64Process;
					info.isWow64Valid = TRUE;
				}
			}

			// Process Image 
					// Process Image 
			{
				// If we're dealing with System (PID 4), we need to get the kernel file name. Otherwise, get the image file name.

				if (info.pid != SYSTEM_PROCESS_ID) {
					if (info.queryHandle && !info.isSubsystemProcess) {
						PWCHAR tmp = nullptr;
						GetProcessImageFileNameWin32((HANDLE)info.queryHandle, &tmp);

						if (tmp) {
							info.processLocation = tmp;
							free(tmp);
						} else {
							info.processLocation = L"";
						}
					} else {
						PWCHAR fileName;
						if (NT_SUCCESS(GetProcessImageFileNameByProcessId((HANDLE)info.pid, &fileName))) {
							PWCHAR tmp = GetFileName(fileName);

							if (fileName) {
								free(fileName);
							}

							if (tmp) {
								info.processLocation = tmp;
								free(tmp);
							} else {
								info.processLocation = L"";
							}
						}
					}
				} else {
					PWCHAR fileName = GetKernelFileName();

					if (fileName) {
						PWCHAR tmp = GetFileName(fileName);

						free(fileName);

						if (tmp) {
							info.processLocation = tmp;
							free(tmp);
						}
						else {
							info.processLocation = L"";
						}
					}
				}
			}

			list.push_back(info);
			pSystemProc = reinterpret_cast<PSYSTEM_PROCESSES>(reinterpret_cast<char *>(pSystemProc) + pSystemProc->NextEntryDelta);
		}
	}

	if (lpSystemInfo != nullptr) {
		free(lpSystemInfo);
	}
	std::cout << "Success enum process";

	return list;
}
