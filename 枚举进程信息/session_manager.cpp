#include "session_manager.h"
#include "session_private.h"

ULONG actived_session_id() {
	PSESSIONIDW sessions;
	ULONG numberOfSessions = 0, SessionId = 0;

	if (WinStationEnumerateW(nullptr, &sessions, &numberOfSessions)) {
		for (ULONG i = 0; i < numberOfSessions; i++) {
			WINSTATIONINFORMATION winStationInfo;
			ULONG returnLength;

			if (!WinStationQueryInformationW(nullptr, sessions[i].SessionId, WinStationInformation, &winStationInfo, sizeof(WINSTATIONINFORMATION), &returnLength)) {
				winStationInfo.Domain[0] = UNICODE_NULL;
				winStationInfo.UserName[0] = UNICODE_NULL;
			}

			if (winStationInfo.Domain[0] == UNICODE_NULL || winStationInfo.UserName[0] == UNICODE_NULL) {
				continue;
			}

			if (winStationInfo.ConnectState == State_Active) {
				SessionId = sessions[i].SessionId;
				break;
			}
		}

		WinStationFreeMemory(sessions);
	}

	return SessionId;
}
