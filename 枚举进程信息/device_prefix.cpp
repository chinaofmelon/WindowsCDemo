#include "device_prefix.h"
#include <iostream>
#include "process_private.h"
#include "windows_version.h"
#include <ntstatus.h>
#include "string_utils.h"

#define MAX_OBJECT_TYPE_NUMBER 257
#define LARGE_BUFFER_SIZE (256 * 1024 * 1024)
#define DEVICE_PREFIX_LENGTH 64

UNICODE_STRING DevicePrefixes[26];
PWCHAR ObjectTypeNames[MAX_OBJECT_TYPE_NUMBER];

NTSTATUS EnumObjectTypes(_Out_ POBJECT_TYPES_INFORMATION *ObjectTypes) {
	NTSTATUS status;
	ULONG bufferSize = 0x1000, returnLength = 0;
	PVOID buffer = malloc(bufferSize);
	memset(buffer, 0, bufferSize);

	while ((status = NtQueryObject(nullptr, ObjectTypesInformation, buffer, bufferSize, &returnLength)) == STATUS_INFO_LENGTH_MISMATCH) {
		free(buffer);
		bufferSize *= 2;

		// Fail if we're resizing the buffer to something very large.
		if (bufferSize > LARGE_BUFFER_SIZE)
			return STATUS_INSUFFICIENT_RESOURCES;

		buffer = malloc(bufferSize);
		memset(buffer, 0, bufferSize);
	}

	if (!NT_SUCCESS(status)) {
		free(buffer);
		return status;
	}

	*ObjectTypes = static_cast<POBJECT_TYPES_INFORMATION>(buffer);

	return status;
}

VOID InitializeTypeNames() {
	if (GetWindowsVersion() >= WINDOWS_8_1) {
		if (ObjectTypeNames[0] == nullptr) {
			POBJECT_TYPES_INFORMATION objectTypes;

			if (NT_SUCCESS(EnumObjectTypes(&objectTypes))) {
				POBJECT_TYPE_INFORMATION objectType = static_cast<POBJECT_TYPE_INFORMATION>(PH_FIRST_OBJECT_TYPE(objectTypes));

				for (ULONG i = 0; i < objectTypes->NumberOfTypes; i++) {
					PWCHAR typeName = static_cast<PWCHAR>(malloc((wcslen(objectType->TypeName.Buffer) + 1) * sizeof(WCHAR)));
					memset(typeName, 0, (wcslen(objectType->TypeName.Buffer) + 1) * sizeof(WCHAR));

					ObjectTypeNames[objectType->TypeIndex] = static_cast<PWCHAR>(memcpy(typeName, objectType->TypeName.Buffer, wcslen(objectType->TypeName.Buffer) * sizeof(WCHAR)));

					objectType = static_cast<POBJECT_TYPE_INFORMATION>(PH_NEXT_OBJECT_TYPE(objectType));
				}

				free(objectTypes);
			}
		}
	}
}

VOID InitializeDevicePrefixes() {
	PUCHAR buffer = (PUCHAR)malloc(DEVICE_PREFIX_LENGTH * sizeof(WCHAR) * 26);
	memset(buffer, 0, DEVICE_PREFIX_LENGTH * sizeof(WCHAR) * 26);

	for (ULONG i = 0; i < 26; i++) {
		DevicePrefixes[i].Length = 0;
		DevicePrefixes[i].MaximumLength = DEVICE_PREFIX_LENGTH * sizeof(WCHAR);
		DevicePrefixes[i].Buffer = (PWCHAR)buffer;
		buffer += DEVICE_PREFIX_LENGTH * sizeof(WCHAR);
	}
}

// 获取所有盘符的前缀，如果没有盘符，空
VOID UpdateDosDevicePrefixes(VOID) {
	WCHAR deviceNameBuffer[7] = L"\\??\\ :";
#ifndef _WIN64
	PROCESS_DEVICEMAP_INFORMATION deviceMapInfo;
#else
	PROCESS_DEVICEMAP_INFORMATION_EX deviceMapInfo;
#endif
	memset(&deviceMapInfo, 0, sizeof(deviceMapInfo));

	NtQueryInformationProcess(NtCurrentProcess(), ProcessDeviceMap, &deviceMapInfo, sizeof(deviceMapInfo), NULL);

	for (ULONG i = 0; i < 0x1A; i++) {
		HANDLE linkHandle;
		OBJECT_ATTRIBUTES oa;
		UNICODE_STRING deviceName;

		if (deviceMapInfo.Query.DriveMap) {
			if (!(deviceMapInfo.Query.DriveMap & (0x1 << i)))
				continue;
		}

		deviceNameBuffer[4] = (WCHAR)('A' + i);
		deviceName.Buffer = deviceNameBuffer;
		deviceName.Length = 6 * sizeof(WCHAR);

		InitializeObjectAttributes(&oa, &deviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

		if (NT_SUCCESS(NtOpenSymbolicLinkObject(&linkHandle, SYMBOLIC_LINK_QUERY, &oa))) {
			if (!NT_SUCCESS(NtQuerySymbolicLinkObject(linkHandle, &DevicePrefixes[i], NULL))) {
				DevicePrefixes[i].Length = 0;
			}

			NtClose(linkHandle);
		}
		else {
			DevicePrefixes[i].Length = 0;
		}
	}
}

VOID InitialDevice() {
	std::cout << "[AKPROCESS] Initialize Device Prefixes\n";
	InitializeDevicePrefixes();
	std::cout << "[AKPROCESS] Initialize Type Names\n";
	InitializeTypeNames();
	std::cout << "[AKPROCESS] Update Dos Device Prefixes\n";
	UpdateDosDevicePrefixes();
}

PWCHAR ResolveDevicePrefix(_In_ PWCHAR Name) {
	ULONG i;
	PWCHAR newName = NULL;

	// Go through the DOS devices and try to find a matching prefix.
	for (i = 0; i < 26; i++) {
		BOOLEAN isPrefix = FALSE;
		PWCHAR prefix = DevicePrefixes[i].Buffer;

		if (wcslen(prefix) != 0) {
			if (IsPrefxContainString(Name, prefix, TRUE)) {
				// To ensure we match the longest prefix, make sure the next character is a
				// backslash or the path is equal to the prefix.
				if (wcslen(Name) == wcslen(prefix) || (wcslen(Name) > wcslen(prefix) && Name[wcslen(prefix)] == OBJ_NAME_PATH_SEPARATOR)) {
					isPrefix = TRUE;
				}
			}
		}

		if (isPrefix) {
			size_t length = (3 + wcslen(Name) - wcslen(prefix)) * sizeof(WCHAR);

			newName = (PWCHAR)malloc(length);
			memset(newName, 0, length);
			newName[0] = (WCHAR)('A' + i);
			newName[1] = ':';
			memcpy(&newName[2], &Name[wcslen(prefix)], (wcslen(Name) - wcslen(prefix)) * sizeof(WCHAR));
			break;
		}
	}

	return newName;
}

PWCHAR GetSystemRoot() {
	static PWCHAR systemRoot;

	if (systemRoot) {
		return systemRoot;
	}

	systemRoot = USER_SHARED_DATA->NtSystemRoot;

	return systemRoot;
}

