// Native transport driver: all inputs (including secrets) arrive on stdin.
// No service installation, registry writes, certificate-store changes, or UI.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <string>
#include "../src/json.hpp"
#include "../windows/maintenance_http.hpp"

namespace {
void erase(std::string& value) { if (!value.empty()) SecureZeroMemory(value.data(), value.size()); }
struct inputs {
    std::string text;
    ohno_json::value json;
    ohno::MaintenanceRequest request;
    ~inputs() {
        erase(text);
        erase(request.password);
        erase(request.device_key);
        for (auto& field : json.fields) erase(field.second.text);
    }
};
std::wstring wide(const std::string& text) {
    if (text.empty() || text.size() > 1024) return {};
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!count) return {};
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), count)) return {};
    return result;
}
}

int main(int argc, char**) {
    try {
        if (argc != 1) { std::puts("InvalidInput"); return 2; }
        inputs data;
        // Read bytewise to enforce a cap before allocating; no secret is ever
        // printed, passed in command-line arguments, or read from environment.
        data.text.reserve(32768);
        for (;;) {
            const int next = std::getchar();
            if (next == EOF) break;
            if (data.text.size() >= 32768) { std::puts("InvalidInput"); return 2; }
            data.text.push_back(static_cast<char>(next));
        }
        data.json = ohno_json::parse(data.text);
        if (data.json.type != ohno_json::value::kind::object || data.json.fields.size() != 7) {
            std::puts("InvalidInput"); return 2;
        }
        const auto field = [&data](const char* name) -> const std::string& {
            const auto& value = data.json.at(name);
            if (value.type != ohno_json::value::kind::string) throw 1;
            return value.text;
        };
        data.request.server = wide(field("server"));
        data.request.certificate_pem = field("certificate_pem");
        data.request.action = field("action");
        data.request.nonce = field("nonce");
        data.request.password = field("password");
        data.request.device_id = field("device_id");
        data.request.device_key = field("device_key");
        switch (ohno::authorize_maintenance(data.request)) {
        case ohno::MaintenanceResult::Authorized: std::puts("Authorized"); return 0;
        case ohno::MaintenanceResult::Denied: std::puts("Denied"); return 10;
        case ohno::MaintenanceResult::Unavailable: std::puts("Unavailable"); return 11;
        case ohno::MaintenanceResult::InvalidResponse: std::puts("InvalidResponse"); return 12;
        }
    } catch (...) {}
    std::puts("InvalidInput");
    return 2;
}
