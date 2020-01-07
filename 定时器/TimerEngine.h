#ifndef __TIMER_ENGINE_H__
#define __TIMER_ENGINE_H__

#include <Windows.h>
#include <map>
#include <queue>

//回调接口
typedef struct ITimerEngineCallBack {
	virtual bool OnTimerEngineCallBack(DWORD TimerID, DWORD Param) = 0;
}*ITimerEngineCallBackPtr;

class TimerEngine {
public:

	TimerEngine();
	virtual ~TimerEngine();

	bool StartEngine();
	bool StopEngine();

	//添加定时器(不同的回调里面不用考虑TimerID重复的问题 )
	bool AddTimer(ITimerEngineCallBackPtr pCallBack, DWORD TimerID, DWORD Interval = 1000, DWORD Times = 1, DWORD Param = 0);
	bool KillTimer(ITimerEngineCallBackPtr pCallBack, DWORD TimerID);

private:
	//添加一个回调
	bool AddCallBack(ITimerEngineCallBackPtr pCallBack, DWORD TimerID, DWORD Param);

	//引擎线程
	static UINT WINAPI EngineThread(LPVOID P);

	//回调线程
	static UINT WINAPI CallBackThread(LPVOID P);

	//定时器数据
	struct TimerDetail {
		DWORD mTimerID;
		DWORD mInterval;
		DWORD mTimes;
		DWORD mParam;
		DWORD mTick;
	};

	//执行数组
	typedef std::multimap< ITimerEngineCallBackPtr, TimerDetail > TimerDetails;
	typedef TimerDetails::iterator TimerDetailsIterator;
	TimerDetails mTimerDetails;

	//执行锁
	CRITICAL_SECTION mTimerDetailsLock;

	//停止事件
	HANDLE mStopEvent;

	//回调事件
	HANDLE mCallBackEvent;

	//回调数据
	struct TimerCallBack {
		ITimerEngineCallBackPtr mpCallBack;
		DWORD mTimerID;
		DWORD mParam;
	};

	//回调队列
	std::queue< TimerCallBack > mTimerCallBacks;

	//回调锁
	CRITICAL_SECTION mTimerCallBacksLock;

	//线程指针
	LPHANDLE mpThread;
};

#endif