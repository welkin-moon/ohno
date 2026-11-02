#pragma once
#include <string>

namespace ohno {
struct MaintenanceRequest {
    std::wstring server;
    // Optional exact server-certificate PEM pin, NOT a CA-store installation.
    std::string certificate_pem;
    std::string action;
    std::string nonce;
    std::string password;
    std::string device_id;
    std::string device_key;
};

enum class MaintenanceResult { Authorized, Denied, Unavailable, InvalidResponse };

// An online, nonce-bound decision, not a reusable token. The caller must generate
// a fresh 32-byte random nonce, act immediately only on Authorized, and erase its
// password/device_key buffers after this call. This function never logs secrets,
// writes persistent state, changes certificate stores, or changes OS permissions.
MaintenanceResult authorize_maintenance(const MaintenanceRequest& request) noexcept;
}
