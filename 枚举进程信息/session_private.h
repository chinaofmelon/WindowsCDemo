#ifndef __SESSION_PROVATE_H__
#define __SESSION_PROVATE_H__

// winsta.lib
#include <Windows.h>

/* ===================================== 私有定义 开始 ========================================================= */
/* ===================================== Windows 未公开的宏定义 开始 ========================================================= */

#define WINSTATIONNAME_LENGTH 32

#define DOMAIN_LENGTH 17
#define USERNAME_LENGTH 20
#define MAX_THINWIRECACHE 4

/* ===================================== Windows 未公开的枚举值 开始 ========================================================= */
typedef WCHAR WINSTATIONNAME[WINSTATIONNAME_LENGTH + 1];

typedef enum _WINSTATIONINFOCLASS {
	WinStationCreateData, // WINSTATIONCREATE
	WinStationConfiguration, // WINSTACONFIGWIRE + USERCONFIG
	WinStationPdParams, // PDPARAMS
	WinStationWd, // WDCONFIG
	WinStationPd, // PDCONFIG2 + PDPARAMS
	WinStationPrinter, // Not supported.
	WinStationClient, // WINSTATIONCLIENT
	WinStationModules,
	WinStationInformation, // WINSTATIONINFORMATION
	WinStationTrace,
	WinStationBeep,
	WinStationEncryptionOff,
	WinStationEncryptionPerm,
	WinStationNtSecurity,
	WinStationUserToken, // WINSTATIONUSERTOKEN
	WinStationUnused1,
	WinStationVideoData, // WINSTATIONVIDEODATA
	WinStationInitialProgram,
	WinStationCd, // CDCONFIG
	WinStationSystemTrace,
	WinStationVirtualData,
	WinStationClientData, // WINSTATIONCLIENTDATA
	WinStationSecureDesktopEnter,
	WinStationSecureDesktopExit,
	WinStationLoadBalanceSessionTarget, // ULONG
	WinStationLoadIndicator, // WINSTATIONLOADINDICATORDATA
	WinStationShadowInfo, // WINSTATIONSHADOW
	WinStationDigProductId, // WINSTATIONPRODID
	WinStationLockedState, // BOOL
	WinStationRemoteAddress, // WINSTATIONREMOTEADDRESS
	WinStationIdleTime, // ULONG
	WinStationLastReconnectType, // ULONG
	WinStationDisallowAutoReconnect, // BOOLEAN
	WinStationMprNotifyInfo,
	WinStationExecSrvSystemPipe,
	WinStationSmartCardAutoLogon,
	WinStationIsAdminLoggedOn,
	WinStationReconnectedFromId, // ULONG
	WinStationEffectsPolicy, // ULONG
	WinStationType, // ULONG
	WinStationInformationEx, // WINSTATIONINFORMATIONEX 
	WinStationValidationInfo
} WINSTATIONINFOCLASS;

typedef enum _WINSTATIONSTATECLASS {
	State_Active = 0,
	State_Connected = 1,
	State_ConnectQuery = 2,
	State_Shadow = 3,
	State_Disconnected = 4,
	State_Idle = 5,
	State_Listen = 6,
	State_Reset = 7,
	State_Down = 8,
	State_Init = 9
} WINSTATIONSTATECLASS;

/* ===================================== Windows 未公开的结构体 开始 ========================================================= */
typedef struct _TSHARE_COUNTERS {
	ULONG Reserved;
} TSHARE_COUNTERS, *PTSHARE_COUNTERS;

typedef struct _PROTOCOLCOUNTERS {
	ULONG WdBytes;
	ULONG WdFrames;
	ULONG WaitForOutBuf;
	ULONG Frames;
	ULONG Bytes;
	ULONG CompressedBytes;
	ULONG CompressFlushes;
	ULONG Errors;
	ULONG Timeouts;
	ULONG AsyncFramingError;
	ULONG AsyncOverrunError;
	ULONG AsyncOverflowError;
	ULONG AsyncParityError;
	ULONG TdErrors;
	USHORT ProtocolType;
	USHORT Length;
	union {
		TSHARE_COUNTERS TShareCounters;
		ULONG Reserved[100];
	} Specific;
} PROTOCOLCOUNTERS, *PPROTOCOLCOUNTERS;

typedef struct _THINWIRECACHE {
	ULONG CacheReads;
	ULONG CacheHits;
} THINWIRECACHE, *PTHINWIRECACHE;

typedef struct _RESERVED_CACHE {
	THINWIRECACHE ThinWireCache[MAX_THINWIRECACHE];
} RESERVED_CACHE, *PRESERVED_CACHE;

typedef struct _TSHARE_CACHE {
	ULONG Reserved;
} TSHARE_CACHE, *PTSHARE_CACHE;

typedef struct CACHE_STATISTICS {
	USHORT ProtocolType;
	USHORT Length;
	union {
		RESERVED_CACHE ReservedCacheStats;
		TSHARE_CACHE TShareCacheStats;
		ULONG Reserved[20];
	} Specific;
} CACHE_STATISTICS, *PCACHE_STATISTICS;

typedef struct _PROTOCOLSTATUS {
	PROTOCOLCOUNTERS Output;
	PROTOCOLCOUNTERS Input;
	CACHE_STATISTICS Cache;
	ULONG AsyncSignal;
	ULONG AsyncSignalMask;
} PROTOCOLSTATUS, *PPROTOCOLSTATUS;

typedef struct _WINSTATIONINFORMATION {
	WINSTATIONSTATECLASS ConnectState;
	WINSTATIONNAME WinStationName;
	ULONG LogonId;
	LARGE_INTEGER ConnectTime;
	LARGE_INTEGER DisconnectTime;
	LARGE_INTEGER LastInputTime;
	LARGE_INTEGER LogonTime;
	PROTOCOLSTATUS Status;
	WCHAR Domain[DOMAIN_LENGTH + 1];
	WCHAR UserName[USERNAME_LENGTH + 1];
	LARGE_INTEGER CurrentTime;
} WINSTATIONINFORMATION, *PWINSTATIONINFORMATION;

typedef struct _SESSIONIDW {
	union {
		ULONG SessionId;
		ULONG LogonId;
	};
	WINSTATIONNAME WinStationName;
	WINSTATIONSTATECLASS State;
} SESSIONIDW, *PSESSIONIDW;

/* ===================================== 私有定义 开始 ========================================================= */

EXTERN_C BOOLEAN WINAPI WinStationQueryInformationW(
	_In_opt_ HANDLE ServerHandle,
	_In_ ULONG SessionId,
	_In_ WINSTATIONINFOCLASS WinStationInformationClass,
	_Out_writes_bytes_(WinStationInformationLength) PVOID pWinStationInformation,
	_In_ ULONG WinStationInformationLength,
	_Out_ PULONG pReturnLength
);

EXTERN_C BOOLEAN WINAPI WinStationEnumerateW(_In_opt_ HANDLE ServerHandle, _Out_ PSESSIONIDW *SessionIds, _Out_ PULONG Count);
EXTERN_C BOOLEAN WINAPI WinStationFreeMemory(_In_ PVOID Buffer);
/* ===================================== Windows 未公开的方法 结束 ========================================================= */

#endif