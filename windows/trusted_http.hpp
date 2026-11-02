#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <functional>
#include <string>
#include <string_view>

namespace ohno {
struct TrustedPost {
    const std::wstring& server;
    const std::string& certificate_pem;
    std::wstring path;
    std::string_view body; // caller owns/wipes secret bytes; no implicit copy
    std::size_t max_response=2048;
    DWORD timeout_ms=20000;
    HANDLE stop_event=nullptr;
    bool binary=false;
};
enum class TrustedHttpFailure { None, Unavailable, InvalidResponse };
struct TrustedHttpResponse {
    TrustedHttpFailure failure=TrustedHttpFailure::Unavailable;
    DWORD status=0;
    std::string body;
};
// Actual request connection is authenticated BEFORE any secret body bytes.
// Fixed OHNO endpoint allowlist, no redirect/proxy/auth replay. Binary success
// requires a bounded sink rather than accumulating a whole package in memory.
TrustedHttpResponse trusted_post(const TrustedPost& request,
    const std::function<bool(const char*,std::size_t)>& sink={}) noexcept;
}
