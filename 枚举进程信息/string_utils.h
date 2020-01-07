#ifndef __STRING_UTILS_H__
#define __STRING_UTILS_H__

#include <Windows.h>

PWCHAR copyString(PWCHAR str);
BOOLEAN IsPrefxContainString(_In_ PWCHAR Source, _In_ PWCHAR Prefix, _In_ BOOLEAN IgnoreCase);

#endif