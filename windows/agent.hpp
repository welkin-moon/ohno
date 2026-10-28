#pragma once
#include <windows.h>
// Runs until stop_event is signaled. Registration/polling only; no enforcement.
void run_agent(HANDLE stop_event);
