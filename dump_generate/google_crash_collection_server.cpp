#include "google_crash_collection_server.h"
#include <string>

#include "google_breakpad/common/minidump_format.h"
#include "client/windows/crash_generation/crash_generation_server.h"
#include "client/windows/handler/exception_handler.h"
#include "client/windows/common/ipc_protocol.h"
#include "client/windows/crash_generation/client_info.h"

const wchar_t kPipeName[] = L"\\\\.\\pipe\\BreakpadCrashServices\\TestServer";

using namespace google_breakpad;

static ::CrashGenerationServer* crash_server = NULL;

static void ShowClientConnected(void* context, const ClientInfo* client_info) {
	printf("Client connected:\t\t%d\r\n", client_info->pid());
}

static void ShowClientCrashed(void* context, const ClientInfo* client_info, const std::wstring* dump_path) {

	CustomClientInfo custom_info = client_info->GetCustomInfo();
	if (custom_info.count <= 0) {
		return;
	}

	std::wstring str_line;
	for (size_t i = 0; i < custom_info.count; ++i) {
		if (i > 0) {
			str_line += L", ";
		}
		str_line += custom_info.entries[i].name;
		str_line += L": ";
		str_line += custom_info.entries[i].value;
	}

	wprintf(str_line.c_str());
	printf("\n");
}

static void ShowClientExited(void* context, const ClientInfo* client_info) {
	printf("Client exited:\t\t%d\r\n", client_info->pid());
}

int google_crash_collection_server() {
	if (crash_server) {
		return 1;
	}

	std::wstring dump_path = L"C:\\Dumps\\server";

	if (_wmkdir(dump_path.c_str()) && (errno != EEXIST)) {
		printf("Unable to create dump directory\n");
		return 1;
	}

	crash_server = new CrashGenerationServer(kPipeName,
		NULL,
		ShowClientConnected,
		NULL,
		ShowClientCrashed,
		NULL,
		ShowClientExited,
		NULL,
		NULL,
		NULL,
		true,
		&dump_path);

	if (!crash_server->Start()) {
		printf("Unable to start server\n");
		delete crash_server;
		crash_server = NULL;
	}

	MSG msg = {0};

	int index = 0;
	while (msg.message != WM_QUIT) { //while we do not close our application
		if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return 0;
}