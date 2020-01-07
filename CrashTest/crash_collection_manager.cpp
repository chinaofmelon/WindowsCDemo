#include "crash_collection_manager.h"
#include <DbgHelp.h>
#include <exception>
#include <cstdio>
#include <string>

static wchar_t *dump_file_path;
static wchar_t *dump_file_exe;
static wchar_t *dump_file_exe_params;

static std::wstring dump_file_path_wstring;
static std::wstring dump_file_exe_wstring;
static std::wstring dump_file_exe_params_wstring;

wchar_t *copy_from_wstring(std::wstring ori) {
	int file_path_len = wcslen(ori.c_str());

	wchar_t *copy_str = static_cast<wchar_t *>(malloc((file_path_len + 1) * sizeof(wchar_t)));
	memset(copy_str, 0, (file_path_len + 1) * sizeof(wchar_t));
	wcscpy(copy_str, ori.c_str());

	return copy_str;
}

void generate_dump_file_path() {
	SYSTEMTIME stSysTime;
	memset(&stSysTime, 0, sizeof(stSysTime));
	GetLocalTime(&stSysTime);

	wchar_t dateString[MAX_PATH] = { 0 };
	wsprintfW(dateString, 
		L"%0.4d-%0.2d-%0.2d-%0.2d-%0.2d-%0.2d-%0.3d", 
		stSysTime.wYear,
		stSysTime.wMonth,
		stSysTime.wDay,
		stSysTime.wHour,
		stSysTime.wMinute,
		stSysTime.wSecond,
		stSysTime.wMilliseconds);

	dump_file_path_wstring = std::wstring(L"C:\\Dumps") +  L"\\Logs\\" + std::wstring(dateString) + L".dmp";
	dump_file_exe_params_wstring = std::to_wstring(GetCurrentProcessId());
	dump_file_exe_wstring = L"dump_generate.exe";

	dump_file_path = copy_from_wstring(dump_file_path_wstring);
	dump_file_exe_params = copy_from_wstring(dump_file_exe_params_wstring);
	dump_file_exe = copy_from_wstring(dump_file_exe_wstring);
}

static int call_to_collect(wchar_t *dump_collect_exe) {
	SHELLEXECUTEINFOW shExecInfo = { 0 };
	shExecInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
	shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;

	shExecInfo.hwnd = nullptr;
	shExecInfo.lpVerb = L"open";
	shExecInfo.lpFile = dump_collect_exe;
	shExecInfo.lpParameters = dump_file_exe_params;
	shExecInfo.lpDirectory = nullptr;
	shExecInfo.nShow = SW_HIDE;
	shExecInfo.hInstApp = nullptr;

	BOOL execSuccess = ShellExecuteExW(&shExecInfo);

	if (execSuccess) {
		WaitForSingleObject(shExecInfo.hProcess, INFINITE);
		DWORD exitCode = 0;
		GetExitCodeProcess(shExecInfo.hProcess, &exitCode);
		if (exitCode == 0) {
			return 0;
		}
	} else {
	}

	return -1;
}

static long __stdcall CrashInfocallback(_EXCEPTION_POINTERS *pexcp) {
	// 创建 Dump 文件

	if (FILE *file = _wfopen(dump_file_exe, L"r")) {
		fclose(file);
		// 进程外收集 dump
		if (call_to_collect(dump_file_exe)) {
			wprintf(L"Collect dump file with other process\n");
			system("pause");
			return 0;
		}
	}

	// 进程内收集 dump
	HANDLE hDumpFile = CreateFileW(
		dump_file_path,
		GENERIC_WRITE,
		0,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (hDumpFile != INVALID_HANDLE_VALUE) {
		// Dump 信息
		MINIDUMP_EXCEPTION_INFORMATION dumpInfo;
		dumpInfo.ExceptionPointers = pexcp;
		dumpInfo.ThreadId = GetCurrentThreadId();
		dumpInfo.ClientPointers = TRUE;
		// 写入 Dump 文件内容
		BOOL writeDump = MiniDumpWriteDump(
			GetCurrentProcess(),
			GetCurrentProcessId(),
			hDumpFile,
			MiniDumpNormal,
			&dumpInfo,
			nullptr,
			nullptr
		);
		int error = GetLastError();
	}
	wprintf(L"Use my self collect dump file at %s\n", dump_file_path);
	system("pause");
	return 0;
}

void DisableSetUnhandledExceptionFilter() {
	try {
		void* addr = (void*)SetUnhandledExceptionFilter;

		if (addr) {
			unsigned char code[16];
			int size = 0;

			code[size++] = 0x33;
			code[size++] = 0xC0;
			code[size++] = 0xC2;
			code[size++] = 0x04;
			code[size++] = 0x00;

			DWORD dwOldFlag, dwTempFlag;
			BOOL result1 = VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &dwOldFlag);
			BOOL result2 = WriteProcessMemory(GetCurrentProcess(), addr, code, size, NULL);
			BOOL result3 = VirtualProtect(addr, size, dwOldFlag, &dwTempFlag);
		}
	} catch (const std::exception& e) {
		// 异常处理
	}
}

int initial_crash_collection() {
	generate_dump_file_path();

	SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)CrashInfocallback);
	DisableSetUnhandledExceptionFilter();

	return 0;
}