#ifndef __DEVICE_PREFIX_H__
#define __DEVICE_PREFIX_H__

#include <Windows.h>

EXTERN_C_START
#define OBJ_NAME_PATH_SEPARATOR ((WCHAR)L'\\')
#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)0x7ffe0000)
EXTERN_C_END

VOID InitialDevice();
PWCHAR ResolveDevicePrefix(_In_ PWCHAR Name);
PWCHAR GetSystemRoot();

#endif