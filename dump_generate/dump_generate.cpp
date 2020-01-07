#include <windows.h>
#include "crash_collection_server.h"
#include "google_crash_collection_server.h"
#include "../CrashTest/use_google_breakpad.h"

int main(int argc, char **argv) {
#if USE_GOOGLEPAD
	google_crash_collection_server();
#else
	DWORD PID = atoi(argv[1]);
	crash_collection_server(PID);
#endif

	return 0;
}
