#pragma once
#include "update_payload.hpp"
namespace ohno {
// Read-only selection for the standard user request launcher. Uses last-good
// during probation; never takes the service's exclusive writer lock.
std::wstring installed_request_helper(const std::wstring& trusted_root,const std::string& public_key);
// After SCM has stopped only. Remove our exact known files from owner-marked
// version/stage directories; never recurse into unknown/reparse contents.
bool remove_installed_payloads(const std::wstring& trusted_root);
}
