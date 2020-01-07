// 定时器.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "TimerEngine.h"
#include "TimerTest.h"


int main() {
	TimerEngine test_timer;

	std::cout << "Start timer!\n";
	test_timer.StartEngine();

	TimerTest *test1 = new TimerTest();
	TimerTest *test2 = new TimerTest();

	test_timer.AddTimer(test1, 0, 1000, INFINITE);
	std::cout << "Add timer 1!\n";
	test_timer.AddTimer(test2, 1, 1000, INFINITE);
	std::cout << "Add timer 2!\n";

	Sleep(10000);

	test_timer.KillTimer(test1, 0);
	std::cout << "Remove timer 1!\n";

	test_timer.KillTimer(test2, 1);
	std::cout << "Remove timer 2!\n";

	test_timer.StopEngine();
	std::cout << "Stop timer!\n";

	delete test1;
	delete test2;

    std::cout << "Finish!\n"; 
}
