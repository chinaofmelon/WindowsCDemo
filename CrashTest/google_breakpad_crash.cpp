#include "google_breakpad_crash.h"
#include "google_breakpad/common/minidump_format.h"
#include "client/windows/crash_generation/crash_generation_client.h"
#include "client/windows/handler/exception_handler.h"
#include "client/windows/common/ipc_protocol.h"

const wchar_t kPipeName[] = L"\\\\.\\pipe\\BreakpadCrashServices\\TestServer";

static size_t kCustomInfoCount = 2;
static google_breakpad::CustomInfoEntry kCustomInfoEntries[] = {
	google_breakpad::CustomInfoEntry(L"prod", L"CrashTestApp"),
	google_breakpad::CustomInfoEntry(L"ver", L"1.0"),
};

bool ShowDumpResults(const wchar_t* dump_path,
	const wchar_t* minidump_id,
	void* context,
	EXCEPTION_POINTERS* exinfo,
	MDRawAssertionInfo* assertion,
	bool succeeded) {
	if (succeeded) {
		printf("dump guid is %ws\n", minidump_id);
	}
	else {
		printf("dump failed\n");
	}
	system("pause");
	return succeeded;
}

int initial_google_crash_collection() {
	using namespace google_breakpad;

	CustomClientInfo custom_info = { kCustomInfoEntries, kCustomInfoCount };

	ExceptionHandler *handle = new ExceptionHandler(L"C:\\dumps\\",
		NULL,
		ShowDumpResults,
		NULL,
		ExceptionHandler::HANDLER_ALL,
		MiniDumpNormal,
		kPipeName,
		&custom_info);

	return 0;
}