#include "TimerEngine.h"

class TimerTest : public ITimerEngineCallBack
{
public:
	TimerTest();
	~TimerTest();

	virtual bool OnTimerEngineCallBack(DWORD TimerID, DWORD Param);
};

