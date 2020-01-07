#include "TimerTest.h"
#include <iostream>
#include <ctime>

TimerTest::TimerTest()
{
}

TimerTest::~TimerTest()
{
}

bool TimerTest::OnTimerEngineCallBack(DWORD TimerID, DWORD Param) {
	time_t currnt_time = time(nullptr);

	std::cout << currnt_time << " Hello World! " << TimerID << " \n";

	return TRUE;
}