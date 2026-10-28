#pragma once
#include <windows.h>
#include <string>
#include <vector>
// Manage only values recorded by this program; return false on invalid input or registry errors.
bool apply_browser_policy_at(HKEY root,const std::wstring& target,const std::wstring& tracker,const std::vector<std::string>& domains);
bool apply_edge_policy(const std::vector<std::string>& domains);
bool clear_edge_policy();
