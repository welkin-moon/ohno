#pragma once
#include <string>

// Sends only to the connected SYSTEM-owned local request pipe. The caller's
// message buffer (which may contain a classroom PIN) is erased on every path.
// This does not authenticate an OS administrator or change machine permissions.
std::string send_teacher_request(std::string& message);
