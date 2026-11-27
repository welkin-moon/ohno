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

enum class ProbeResult { Ok, InvalidServer, Unreachable, CertHostMismatch, CertExpired, InvalidResponse };

struct TeacherBootstrapInfo {
    ProbeResult status = ProbeResult::Unreachable;
    std::wstring normalized_server;
    std::string certificate_pem;
    std::wstring fingerprint; // e.g. L"A1B2-C3D4-E5F6-7890"
    std::string release_public_key;
    bool maintenance_configured = false;
};

// Normalize user input like "10.181.203.70" or "teacher-pc:8443" into "https://<host>:<port>".
std::wstring normalize_teacher_origin(const std::wstring& input);

// Compute formatted SHA-256 fingerprint (XXXX-XXXX-XXXX-XXXX) of a PEM certificate.
std::wstring pem_certificate_fingerprint(const std::string& pem);

// Connect to /api/bootstrap with zero secrets sent, retrieve the actual negotiated
// leaf certificate and public trust metadata so the user can visually verify the
// fingerprint against the teacher dashboard without hunting for a .pem file.
TeacherBootstrapInfo probe_teacher_bootstrap(const std::wstring& server_input) noexcept;

// An online, nonce-bound decision, not a reusable token. The caller must generate
// a fresh 32-byte random nonce, act immediately only on Authorized, and erase its
// password/device_key buffers after this call. This function never logs secrets,
// writes persistent state, changes certificate stores, or changes OS permissions.
MaintenanceResult authorize_maintenance(const MaintenanceRequest& request) noexcept;
}
