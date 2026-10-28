#pragma once
#include <windows.h>
#include <string>
#include <vector>
// Best-effort process monitoring: reports the SHA-256 of processes stopped.
std::vector<std::string> stop_matching_processes(const std::vector<std::string>& blocked, const std::vector<std::string>& names, const std::vector<std::string>& allowed, DWORD only_pid = 0);
struct UntrustedProgram { std::wstring path; std::string hash; };
std::vector<UntrustedProgram> observe_untrusted_programs();
