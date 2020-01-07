// 枚举进程信息.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "process_info.h"

int main()
{
	InitialDevice();

	const HANDLE bExitCode = OpenProcess(PROCESS_TERMINATE, FALSE, 12012);
	DWORD returnCode{};
	const BOOL bCode = GetExitCodeProcess((HANDLE)12012, &returnCode);
	int code = GetLastError();
	if (bCode) {
		if (returnCode != STILL_ACTIVE) {


			if (nullptr != bExitCode) {
				std::wcout << L"process name: 12012\n";
			}
		}
	}

	// 如遇中文无法显示，打开该注释
	//std::wcout.imbue(std::locale("chs"));

	std::vector<ak_process_info>infos = enum_process_info();
	std::vector<ak_process_info>infos2 = enum_process_info_with_nt_query();

	std::wcout << L"==================Begin to enum process info 1 ===================\n";

	for (ak_process_info info : infos) {
		std::wcout << L"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";

		std::wcout << L"pid: " << info.pid << "\n";
		std::wcout << L"ppid: " << info.ppid << "\n";
		std::wcout << L"process name: " << info.processName << L"\n";
		std::wcout << L"process image location: " << info.processLocation << L"\n";
		std::wcout << L"handle valid: " << info.isHandleValid << "\n";
		std::wcout << L"wow64: " << info.isWow64 << "\n";
		std::wcout << L"wow64 valid: " << info.isWow64Valid << "\n";
		std::wcout << L"protected process: " << info.isProtectedProcess << "\n";
		std::wcout << L"secure process: " << info.isSecureProcess << "\n";
		std::wcout << L"sub system process: " << info.isSubsystemProcess << "\n";
	}
	std::wcout << L"==================End to enum process info 1 ===================\n";

	std::wcout << L"==================Begin to enum process info 2 ===================\n";

	for (ak_process_info info : infos2) {
		std::wcout << L"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";

		std::wcout << L"pid: " << info.pid << "\n";
		std::wcout << L"ppid: " << info.ppid << "\n";
		std::wcout << L"process name: " << info.processName << L"\n";
		std::wcout << L"process image location: " << info.processLocation << L"\n";
		std::wcout << L"handle valid: " << info.isHandleValid << "\n";
		std::wcout << L"wow64: " << info.isWow64 << "\n";
		std::wcout << L"wow64 valid: " << info.isWow64Valid << "\n";
		std::wcout << L"protected process: " << info.isProtectedProcess << "\n";
		std::wcout << L"secure process: " << info.isSecureProcess << "\n";
		std::wcout << L"sub system process: " << info.isSubsystemProcess << "\n";
	}
	std::wcout << L"==================End to enum process info 2 ===================\n";

    std::wcout << L"Hello World!\n";
	system("pause");
	return 0;
}
