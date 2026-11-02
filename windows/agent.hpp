#pragma once
#include <windows.h>
#include <functional>
// Runs until stop_event is signaled. Reports health only after a successful local enforcement cycle.
void run_agent(HANDLE stop_event,const std::function<void()>& healthy_cycle={},bool trial=false);
