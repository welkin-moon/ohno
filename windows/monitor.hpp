#pragma once
#include <windows.h>
#include <string>
#include <vector>
// Best-effort process monitoring: reports the SHA-256 and name of stopped processes.
struct BlockedProgram { std::string hash; std::wstring name; };
std::vector<BlockedProgram> stop_matching_processes(const std::vector<std::string>& blocked, const std::vector<std::string>& names, const std::vector<std::string>& allowed, DWORD only_pid = 0, HANDLE stop_event = nullptr);
struct UntrustedProgram { std::wstring path; std::string hash; DWORD pid; };
std::vector<UntrustedProgram> observe_untrusted_programs(HANDLE stop_event = nullptr);
void notify_network_block(DWORD pid);
