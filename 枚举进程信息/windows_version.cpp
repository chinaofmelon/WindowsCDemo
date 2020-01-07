#include "windows_version.h"
#include <iostream>
#include "process_private.h"

ULONG WindowsVersion;

RTL_OSVERSIONINFOEXW osVersion = { 0 };

VOID InitializeWindowsVersion() {
	RTL_OSVERSIONINFOEXW versionInfo;

	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

	if (!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&versionInfo))) {
		WindowsVersion = WINDOWS_NEW;
		std::cout << "Failed to get system version. I guess is the newest system\n";
		return;
	}

	memcpy(&osVersion, &versionInfo, sizeof(RTL_OSVERSIONINFOEXW));
	const ULONG major_version = versionInfo.dwMajorVersion;
	const ULONG minor_version = versionInfo.dwMinorVersion;
	const ULONG build_version = versionInfo.dwBuildNumber;

	if (major_version == 6 && minor_version == 1) {
		// Windows 7, Windows Server 2008 R2
		WindowsVersion = WINDOWS_7;
		std::cout << "Current system is WINDOWS_7\n";
	} else if (major_version == 6 && minor_version == 2) {
		// Windows 8, Windows Server 2012
		WindowsVersion = WINDOWS_8;
		std::cout << "Current system is WINDOWS_8\n";
	} else if (major_version == 6 && minor_version == 3) {
		// Windows 8.1, Windows Server 2012 R2
		WindowsVersion = WINDOWS_8_1;
		std::cout << "Current system is WINDOWS_8_1\n";
	} else if (major_version == 10 && minor_version == 0) {
		// Windows 10, Windows Server 2016
		switch (build_version) {
		case 10240:
			WindowsVersion = WINDOWS_10;
			std::cout << "Current system is WINDOWS_10\n";
			break;
		case 10586:
			WindowsVersion = WINDOWS_10_TH2;
			std::cout << "Current system is WINDOWS_10_TH2\n";
			break;
		case 14393:
			WindowsVersion = WINDOWS_10_RS1;
			std::cout << "Current system is WINDOWS_10_RS1\n";
			break;
		case 15063:
			WindowsVersion = WINDOWS_10_RS2;
			std::cout << "Current system is WINDOWS_10_RS2\n";
			break;
		case 16299:
			WindowsVersion = WINDOWS_10_RS3;
			std::cout << "Current system is WINDOWS_10_RS3\n";
			break;
		case 17134:
			WindowsVersion = WINDOWS_10_RS4;
			std::cout << "Current system is WINDOWS_10_RS4\n";
			break;
		default:
			if (build_version > 17134) {
				WindowsVersion = WINDOWS_10_RS5;
				std::cout << "Current system is " << "WINDOWS_10_RS5\n";
			}
			else {
				WindowsVersion = WINDOWS_10;
				std::cout << "Current system is " << "WINDOWS_10\n";
			}

			break;
		}
	} else {
		WindowsVersion = WINDOWS_NEW;
		std::cout << "Unrecognized current system. I guess is the newest system\n";
	}
}

