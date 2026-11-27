#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "../src/feature_match.hpp"

// Hash a stable on-disk image, returning empty if unavailable or cancelled.
// This is not a measurement of an already mapped process image.
std::string program_image_hash(const std::wstring& path, HANDLE stop_event = nullptr);

// Extract executable metadata (PE VersionInfo, Authenticode signer, window title).
ohno::ProcessFeatures extract_process_features(DWORD pid, const std::wstring& image_path);

// Name/feature/whitelist rules still apply when a hash cannot be obtained; those records
// have an empty hash and cannot be submitted for a hash-scoped temporary approval.
struct BlockedProgram { std::string hash; std::wstring name; };

std::vector<BlockedProgram> stop_matching_processes(const ohno::ProcessRuleSet& rules, DWORD only_pid = 0, HANDLE stop_event = nullptr);

// Legacy blacklist-only helper retained for compatibility with existing tests.
std::vector<BlockedProgram> stop_matching_processes(const std::vector<std::string>& blocked, const std::vector<std::string>& names, const std::vector<std::string>& allowed, DWORD only_pid = 0, HANDLE stop_event = nullptr);

struct UntrustedProgram { std::wstring path; std::string hash; DWORD pid; };
std::vector<UntrustedProgram> observe_untrusted_programs(HANDLE stop_event = nullptr);
void notify_network_block(DWORD pid);
