#ifndef __WINDOWS_VERSION_H__
#define __WINDOWS_VERSION_H__

#include <Windows.h>
extern ULONG WindowsVersion;

typedef enum {
	WINDOWS_ANCIENT = 0,
	WINDOWS_XP = 51,
	WINDOWS_VISTA = 60,
	WINDOWS_7 = 61,
	WINDOWS_8 = 62,
	WINDOWS_8_1 = 63,
	WINDOWS_10 = 100, // TH1
	WINDOWS_10_TH2 = 101,
	WINDOWS_10_RS1 = 102,
	WINDOWS_10_RS2 = 103,
	WINDOWS_10_RS3 = 104,
	WINDOWS_10_RS4 = 105,
	WINDOWS_10_RS5 = 106,
	WINDOWS_NEW = MAXLONG,
} WindowsVersionNumber;

VOID InitializeWindowsVersion();

EXTERN_C FORCEINLINE ULONG GetWindowsVersion() {
	if (WindowsVersion == 0) {
		InitializeWindowsVersion();
	}
	return WindowsVersion;
}

#endif