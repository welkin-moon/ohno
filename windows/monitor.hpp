#pragma once
#include <windows.h>
#include <string>
#include <vector>
// Best-effort process monitoring: reports the SHA-256 of processes stopped.
std::vector<std::string> stop_matching_processes(const std::vector<std::string>& blocked, DWORD only_pid = 0);
