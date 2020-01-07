#include "TimerEngine.h"
#include <process.h>
#include <assert.h>

enum eTime
{
	ePRECISION = 32,			//定时器精度,越小精度越高当然消耗CPU越高,根据实际情况调整
	eTHREAD_TIME_OUT = 1024,	//线程超时时间
};

TimerEngine::TimerEngine()
{}

TimerEngine::~TimerEngine()
{}

bool TimerEngine::StartEngine()
{
	InitializeCriticalSection(&mTimerDetailsLock);
	InitializeCriticalSection(&mTimerCallBacksLock);

	mStopEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	mCallBackEvent = CreateSemaphore(NULL, 0, 0xFFFF, NULL);

	if (NULL == mStopEvent || NULL == mCallBackEvent)
	{
		assert(false);
		return false;
	}

	mpThread = new HANDLE[2];

	mpThread[0] = reinterpret_cast<HANDLE>(_beginthreadex(NULL, 0, EngineThread, this, 0, NULL));

	mpThread[1] = reinterpret_cast<HANDLE>(_beginthreadex(NULL, 0, CallBackThread, this, 0, NULL));

	if (NULL == mpThread[0] || NULL == mpThread[1])
	{
		assert(false);
		return false;
	}

	return true;
}

bool TimerEngine::StopEngine() {
	SetEvent(mStopEvent);

	if (WAIT_TIMEOUT == WaitForMultipleObjects(2, mpThread, TRUE, eTHREAD_TIME_OUT)) {
		TerminateThread(mpThread[0], 0);
		TerminateThread(mpThread[1], 0);
	}
	CloseHandle(mpThread[0]);
	CloseHandle(mpThread[1]);
	CloseHandle(mCallBackEvent);
	CloseHandle(mStopEvent);
	delete[] mpThread;
	mpThread = NULL;
	mTimerDetails.clear();
	while (!mTimerCallBacks.empty()) {
		mTimerCallBacks.pop();
	}

	DeleteCriticalSection(&mTimerDetailsLock);
	DeleteCriticalSection(&mTimerCallBacksLock);
	return true;
}

bool TimerEngine::AddTimer(ITimerEngineCallBackPtr pCallBack, DWORD TimerID, DWORD Interval, DWORD Times, DWORD Param) {
	if (nullptr == pCallBack) {
		assert(false);
		return false;
	}

	TimerDetail Timer;
	Timer.mTimerID = TimerID;
	Timer.mInterval = Interval;
	Timer.mTimes = Times;
	Timer.mParam = Param;
	Timer.mTick = GetTickCount();

	EnterCriticalSection(&mTimerDetailsLock);
	std::pair< TimerDetailsIterator, TimerDetailsIterator > Search = mTimerDetails.equal_range(pCallBack);
	bool IsFind = false;
	for (TimerDetailsIterator i = Search.first; i != Search.second; ++i) {
		if (i->second.mTimerID == TimerID) {
			memcpy_s(&i->second, sizeof(i->second), &Timer, sizeof(Timer));
			IsFind = true;
			break;
		}
	}

	if (false == IsFind) {
		mTimerDetails.insert(std::make_pair(pCallBack, Timer));
	}
	LeaveCriticalSection(&mTimerDetailsLock);
	return true;
}

bool TimerEngine::KillTimer(ITimerEngineCallBackPtr pCallBack, DWORD TimerID)
{
	if (NULL == pCallBack)
	{
		assert(false);
		return false;
	}

	EnterCriticalSection(&mTimerDetailsLock);
	std::pair< TimerDetailsIterator, TimerDetailsIterator > Search = mTimerDetails.equal_range(pCallBack);
	for (TimerDetailsIterator i = Search.first; i != Search.second; ++i)
	{
		if (i->second.mTimerID == TimerID)
		{
			mTimerDetails.erase(i);
			break;
		}
	}
	LeaveCriticalSection(&mTimerDetailsLock);
	return true;
}

bool TimerEngine::AddCallBack(ITimerEngineCallBackPtr pCallBack, DWORD TimerID, DWORD Param)
{
	TimerCallBack CallBack = { pCallBack, TimerID, Param };
	EnterCriticalSection(&mTimerCallBacksLock);
	mTimerCallBacks.push(CallBack);
	LeaveCriticalSection(&mTimerCallBacksLock);
	if (FALSE == ReleaseSemaphore(mCallBackEvent, 1, NULL))
	{
		assert(false);
		return false;
	}
	return true;
}

UINT WINAPI TimerEngine::EngineThread(LPVOID P)
{
	TimerEngine *This = static_cast<TimerEngine*>(P);

	HANDLE &WaitObject = This->mStopEvent;
	TimerDetails &Details = This->mTimerDetails;
	CRITICAL_SECTION &Lock = This->mTimerDetailsLock;

	while (true)
	{
		switch (WaitForSingleObject(WaitObject, ePRECISION))
		{
		case WAIT_OBJECT_0:
		{
			return 0;
		}
		break;
		case WAIT_TIMEOUT:
		{
			EnterCriticalSection(&Lock);
			for (TimerDetailsIterator i = Details.begin(); i != Details.end(); )
			{
				if (GetTickCount() - i->second.mTick < i->second.mInterval)
				{
					++i;
					continue;
				}
				This->AddCallBack(i->first, i->second.mTimerID, i->second.mParam);

				i->second.mTick = GetTickCount();

				if (INFINITE == i->second.mTimes)
				{
					++i;
					continue;
				}
				--i->second.mTimes;
				if (0 == i->second.mTimes)
				{
					i = Details.erase(i);
					continue;
				}
				++i;
			}
			LeaveCriticalSection(&Lock);
		}
		break;
		default:
		{
			assert(false);
			return 0;
		}
		break;
		}
	}
	return 0;
}

UINT WINAPI TimerEngine::CallBackThread(LPVOID P)
{
	TimerEngine *This = static_cast<TimerEngine*>(P);

	HANDLE WaitObjects[] = { This->mStopEvent, This->mCallBackEvent };
	std::queue< TimerCallBack > &TimerCallBacks = This->mTimerCallBacks;
	CRITICAL_SECTION &Lock = This->mTimerCallBacksLock;

	TimerCallBack CallBack = {};

	while (true)
	{
		switch (WaitForMultipleObjects(2, WaitObjects, FALSE, INFINITE))
		{
		case WAIT_OBJECT_0:
		{
			return 0;
		}
		break;
		case WAIT_OBJECT_0 + 1:
		{
			EnterCriticalSection(&Lock);
			memcpy_s(&CallBack, sizeof(CallBack), &TimerCallBacks.front(), sizeof(TimerCallBacks.front()));
			TimerCallBacks.pop();
			LeaveCriticalSection(&Lock);
			CallBack.mpCallBack->OnTimerEngineCallBack(CallBack.mTimerID, CallBack.mParam);
		}
		break;
		default:
		{
			assert(false);
			return 0;
		}
		break;
		}
	}
	return 0;
}

