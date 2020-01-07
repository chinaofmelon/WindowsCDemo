// CrashTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "crash_collection_manager.h"
#include "google_breakpad_crash.h"
#include "use_google_breakpad.h"

int main() {

#if USE_GOOGLEPAD
	initial_google_crash_collection();
#else
	initial_crash_collection();
#endif

	printf("Ready to crash the app.\n");

	system("pause");

	int* x = 0;
	*x = 1;

    std::cout << "Hello World!\n";

	system("pause");

	return 0;
}
