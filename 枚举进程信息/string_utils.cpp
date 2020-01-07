#include "string_utils.h"


PWCHAR copyString(PWCHAR str) {
	PWCHAR tmpStr = str ? str : (PWCHAR)L"";

	size_t length = wcslen(tmpStr) * sizeof(WCHAR);
	PWCHAR value = static_cast<PWCHAR>(malloc(length + 2));
	memset(value, 0, length + 2);
	memcpy(value, tmpStr, length);
	return value;
}

BOOLEAN IsPrefxContainString(_In_ PWCHAR Source, _In_ PWCHAR Prefix, _In_ BOOLEAN IgnoreCase) {
	PWCHAR p1 = Source;
	PWCHAR p2 = Prefix;
	SIZE_T l1 = wcslen(Source), l2 = wcslen(Prefix);

	if (l1 < l2) {
		return FALSE;
	}

	for (size_t i = 0; i < l2; i++) {
		WCHAR c1 = *p1;
		WCHAR c2 = *p2;
		if (IgnoreCase) {
			if (c1 >= 'A' && c1 <= 'Z') {
				c1 += 'a' - 'A';
			}
			if (c2 >= 'A' && c2 <= 'Z') {
				c2 += 'a' - 'A';
			}
		}

		if (c1 != c2) {
			return FALSE;
		}
		p1++;
		p2++;
	}
	return TRUE;
}
