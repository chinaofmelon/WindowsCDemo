#include "process_info_manager.h"
#include "process_private.h"
#include "device_prefix.h"
#include <ntstatus.h>
#include "string_utils.h"

NTSTATUS EnumKernelModules(_Out_ PRTL_PROCESS_MODULES *Modules) {
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize = 2048;

	buffer = (PVOID)malloc(bufferSize);
	memset(buffer, 0, bufferSize);

	status = NtQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		free(buffer);
		buffer = (PVOID)malloc(bufferSize);
		memset(buffer, 0, bufferSize);

		status = NtQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
	}

	if (!NT_SUCCESS(status))
		return status;

	*Modules = (PRTL_PROCESS_MODULES)buffer;

	return status;
}

PWCHAR ConvertMultiByteToUtf16Ex(_In_ PCHAR Buffer, _In_ SIZE_T Length) {
	ULONG unicodeBytes;

	NTSTATUS status = RtlMultiByteToUnicodeSize(&unicodeBytes, Buffer, static_cast<ULONG>(Length));

	if (!NT_SUCCESS(status))
		return nullptr;

	PWCHAR string = static_cast<PWCHAR>(malloc((unicodeBytes + 1) * sizeof(WCHAR)));
	memset(string, 0, (unicodeBytes + 1) * sizeof(WCHAR));
	status = RtlMultiByteToUnicodeN(string, unicodeBytes, nullptr, Buffer, static_cast<ULONG>(Length));

	if (!NT_SUCCESS(status)) {
		free(string);
		return nullptr;
	}

	return string;
}

EXTERN_C FORCEINLINE PWCHAR ConvertMultiByteToUtf16(_In_ PSTR Buffer) {
	return ConvertMultiByteToUtf16Ex(Buffer, strlen(Buffer));
}

/**
  * 根据 ProcessId 获取 ProcessHandle
  * 本方法参考了 ProcessHacker 中的 native.c 的 PhOpenProcess 方法
*/
NTSTATUS AKOpenProcess(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ HANDLE ProcessId) {
	OBJECT_ATTRIBUTES objectAttributes;
	CLIENT_ID clientId;

	clientId.UniqueProcess = ProcessId;
	clientId.UniqueThread = nullptr;

	InitializeObjectAttributes(&objectAttributes, nullptr, 0, nullptr, nullptr);
	return NtOpenProcess(ProcessHandle, DesiredAccess, &objectAttributes, &clientId);
}

NTSTATUS QueryProcessVariableSize(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PVOID *Buffer) {
	NTSTATUS status;
	ULONG returnLength = 0;

	status = NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, NULL, 0, &returnLength);

	if (status != STATUS_BUFFER_OVERFLOW && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_INFO_LENGTH_MISMATCH)
		return status;

	PVOID buffer = static_cast<PVOID>(malloc(returnLength));
	memset(buffer, 0, returnLength);
	status = NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, buffer, returnLength, &returnLength);

	if (!NT_SUCCESS(status)) {
		free(buffer);
		buffer = NULL;
	}
	*Buffer = buffer;

	return status;
}

NTSTATUS GetProcessImageFileNameWin32(_In_ HANDLE ProcessHandle, _Out_ PWCHAR *FileName) {
	PVOID fileName;

	const NTSTATUS status = QueryProcessVariableSize(ProcessHandle, ProcessImageFileNameWin32, &fileName);

	PUNICODE_STRING f = static_cast<PUNICODE_STRING>(fileName);
	if (!NT_SUCCESS(status))
		return status;

	*FileName = copyString(f->Buffer);
	free(fileName);

	return status;
}

NTSTATUS GetProcessImageFileNameByProcessId(_In_ HANDLE ProcessId, _Out_ PWCHAR *FileName) {
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize = 0x100;
	SYSTEM_PROCESS_ID_INFORMATION processIdInfo;

	buffer = (PVOID)malloc(bufferSize);
	memset(buffer, 0, bufferSize);

	processIdInfo.ProcessId = ProcessId;
	processIdInfo.ImageName.Length = 0;
	processIdInfo.ImageName.MaximumLength = (USHORT)bufferSize;
	processIdInfo.ImageName.Buffer = (PWSTR)buffer;

	status = NtQuerySystemInformation(SystemProcessIdInformation, &processIdInfo, sizeof(SYSTEM_PROCESS_ID_INFORMATION), NULL);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		// Required length is stored in MaximumLength.

		free(buffer);
		buffer = (PVOID)malloc(processIdInfo.ImageName.MaximumLength);
		memset(buffer, 0, processIdInfo.ImageName.MaximumLength);
		processIdInfo.ImageName.Buffer = (PWSTR)buffer;

		status = NtQuerySystemInformation(SystemProcessIdInformation, &processIdInfo, sizeof(SYSTEM_PROCESS_ID_INFORMATION), NULL);
	}

	if (!NT_SUCCESS(status)) {
		free(buffer);
		return status;
	}

	*FileName = copyString(processIdInfo.ImageName.Buffer);
	free(buffer);

	return status;
}

PWCHAR GetFileName(_In_ PWCHAR FileName) {
	PWCHAR newFileName = FileName;

	if (IsPrefxContainString(FileName, (PWCHAR)L"\\??\\", FALSE)) {
		// "\??\" refers to \GLOBAL??\. 移除
		size_t length = (wcslen(FileName) - 4) * sizeof(WCHAR);
		newFileName = (PWCHAR)malloc(length + sizeof(WCHAR));
		memset(newFileName, 0, length + sizeof(WCHAR));

		memcpy(newFileName, &FileName[4], length);
	}
	else if (IsPrefxContainString(FileName, (PWCHAR)(L"\\SystemRoot"), TRUE)) {
		// "\SystemRoot" 替换成 "C:\Windows".
		PWCHAR systemRoot = GetSystemRoot();
		size_t rootLength = wcslen(systemRoot) * sizeof(WCHAR);
		size_t fileLength = (wcslen(FileName) - 11) * sizeof(WCHAR);

		newFileName = (PWCHAR)malloc(rootLength + fileLength + sizeof(WCHAR));
		memset(newFileName, 0, rootLength + fileLength + sizeof(WCHAR));

		memcpy(newFileName, systemRoot, rootLength);
		memcpy(newFileName + wcslen(systemRoot), &FileName[11], fileLength);
	}
	else if (IsPrefxContainString(FileName, (PWCHAR)L"system32\\", TRUE)) {
		// "system32\" 替换成 "C:\Windows\system32\".
		PWCHAR systemRoot = GetSystemRoot();

		size_t rootLength = wcslen(systemRoot) * sizeof(WCHAR);
		size_t fileLength = (wcslen(FileName) + 1) * sizeof(WCHAR);

		newFileName = (PWCHAR)malloc(rootLength + fileLength + sizeof(WCHAR));
		memset(newFileName, 0, rootLength + fileLength + sizeof(WCHAR));

		memcpy(newFileName, systemRoot, rootLength);
		newFileName[wcslen(systemRoot)] = OBJ_NAME_PATH_SEPARATOR;
		memcpy(newFileName + wcslen(systemRoot) + 1, FileName, wcslen(FileName) * sizeof(WCHAR));
	}
	else if (wcslen(FileName) != 0 && FileName[0] == OBJ_NAME_PATH_SEPARATOR) {
		// TODO: 没看懂。源代码位于 native.c 5520 行
		PWCHAR resolvedName = ResolveDevicePrefix(FileName);

		if (resolvedName) {
			newFileName = resolvedName;
		}
		else {
			// We didn't find a match.
			// If the file name starts with "\Windows", prepend the system drive.
			if (IsPrefxContainString(newFileName, (PWCHAR)L"\\Windows", TRUE)) {
				size_t length = (2 + wcslen(FileName)) * sizeof(WCHAR);

				newFileName = (PWCHAR)malloc(length);
				memset(newFileName, 0, length);
				newFileName[0] = USER_SHARED_DATA->NtSystemRoot[0];
				newFileName[1] = ':';
				memcpy(&newFileName[2], &FileName, wcslen(FileName) * sizeof(WCHAR));
			}
			else {
				newFileName = copyString(FileName);
			}
		}
	}
	else {
		// Just return the supplied file name. Note that we need to add a reference.
		newFileName = copyString(FileName);
	}

	return newFileName;
}

PWCHAR GetKernelFileName() {
	PRTL_PROCESS_MODULES modules;
	PWCHAR fileName = NULL;

	if (!NT_SUCCESS(EnumKernelModules(&modules)))
		return NULL;

	if (modules->NumberOfModules >= 1) {
		fileName = ConvertMultiByteToUtf16((PSTR)modules->Modules[0].FullPathName);
	}

	free(modules);

	return fileName;
}
