#pragma once
#include <windows.h>
#include <string>

// Sends only to the connected SYSTEM-owned local request pipe. The caller's
// message buffer (which may contain a classroom PIN) is erased on every path.
// This does not authenticate an OS administrator or change machine permissions.
// Cancellation/timeout stop waiting, not an operation already sent to a teacher.
// No automatic retry. Use a worker thread; cancelled I/O must drain safely.
std::string send_teacher_request(std::string& message,HANDLE cancel=nullptr,DWORD timeout_ms=25000);
