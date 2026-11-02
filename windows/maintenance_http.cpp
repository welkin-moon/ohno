#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include "maintenance_http.hpp"
#include "../src/json.hpp"
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

namespace {
constexpr std::size_t max_body = 2048;
constexpr ULONGLONG total_timeout_ms = 20000;

struct http_handle {
    HINTERNET value = nullptr;
    explicit http_handle(HINTERNET handle) : value(handle) {}
    ~http_handle() { if (value) WinHttpCloseHandle(value); }
    http_handle(const http_handle&) = delete;
    http_handle& operator=(const http_handle&) = delete;
};
struct certificate {
    PCCERT_CONTEXT value = nullptr;
    ~certificate() { if (value) CertFreeCertificateContext(value); }
    certificate() = default;
    certificate(const certificate&) = delete;
    certificate& operator=(const certificate&) = delete;
};
struct secret_body {
    std::string value;
    ~secret_body() { if (!value.empty()) SecureZeroMemory(value.data(), value.size()); }
};

bool lower_hex(const std::string& text, std::size_t length) {
    return text.size() == length && std::all_of(text.begin(), text.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

// Match the server's character-count and UTF-8 limits without making a second
// plaintext password copy. Reject malformed UTF-8, overlong encodings/surrogates.
bool valid_password(const std::string& text) {
    if (text.size() > 512) return false;
    std::size_t characters = 0;
    for (std::size_t pos = 0; pos < text.size(); ++characters) {
        unsigned char lead = static_cast<unsigned char>(text[pos++]);
        if (lead < 32 || lead == 127) return false;
        if (lead < 128) continue;
        unsigned count = 0, code = 0, minimum = 0;
        if (lead >= 0xc2 && lead <= 0xdf) { count = 1; code = lead & 31; minimum = 0x80; }
        else if (lead >= 0xe0 && lead <= 0xef) { count = 2; code = lead & 15; minimum = 0x800; }
        else if (lead >= 0xf0 && lead <= 0xf4) { count = 3; code = lead & 7; minimum = 0x10000; }
        else return false;
        if (text.size() - pos < count) return false;
        for (unsigned index = 0; index < count; ++index) {
            unsigned char next = static_cast<unsigned char>(text[pos++]);
            if ((next & 0xc0) != 0x80) return false;
            code = (code << 6) | (next & 63);
        }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return false;
    }
    return characters >= 12 && characters <= 128;
}

void append_quoted(std::string& output, const std::string& text) {
    output += '"';
    // Inputs are already valid UTF-8 and contain no control characters.
    for (char ch : text) {
        if (ch == '"' || ch == '\\') output += '\\';
        output += ch;
    }
    output += '"';
}

bool parse_origin(const std::wstring& url, std::wstring& host, INTERNET_PORT& port) {
    if (url.empty() || url.size() > 1024 ||
        std::any_of(url.begin(), url.end(), [](wchar_t ch) { return ch <= 32 || ch == 127 || ch == L'\\'; })) return false;
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = parts.dwHostNameLength = parts.dwUserNameLength =
        parts.dwPasswordLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &parts) ||
        parts.nScheme != INTERNET_SCHEME_HTTPS || !parts.dwHostNameLength ||
        parts.dwUserNameLength || parts.dwPasswordLength || parts.dwExtraInfoLength ||
        parts.dwUrlPathLength > 1 ||
        (parts.dwUrlPathLength == 1 && *parts.lpszUrlPath != L'/')) return false;
    // An empty user-info component (https://@host) is also forbidden. Percent
    // escaping is not meaningful in the fixed origin and can hide delimiters.
    if (url.find(L'@') != std::wstring::npos || url.find(L'%') != std::wstring::npos ||
        url.find(L'?') != std::wstring::npos || url.find(L'#') != std::wstring::npos) return false;
    host.assign(parts.lpszHostName, parts.dwHostNameLength);
    port = parts.nPort;
    return port != 0;
}

bool parse_pin(const std::string& pem, certificate& result) {
    if (pem.empty() || pem.size() > 16384 || pem.find('\0') != std::string::npos) return false;
    constexpr char begin[] = "-----BEGIN CERTIFICATE-----";
    constexpr char end[] = "-----END CERTIFICATE-----";
    const auto first = pem.find_first_not_of(" \t\r\n");
    const auto last = pem.find_last_not_of(" \t\r\n");
    if (first == std::string::npos || pem.compare(first, sizeof(begin) - 1, begin) != 0) return false;
    const auto finish = pem.find(end, first + sizeof(begin) - 1);
    if (finish == std::string::npos || finish + sizeof(end) - 2 != last ||
        pem.find(begin, first + sizeof(begin) - 1) != std::string::npos) return false;
    DWORD size = 0;
    constexpr DWORD flags = CRYPT_STRING_BASE64HEADER | CRYPT_STRING_STRICT;
    if (!CryptStringToBinaryA(pem.data(), static_cast<DWORD>(pem.size()), flags, nullptr, &size, nullptr, nullptr) ||
        !size || size > 12288) return false;
    std::vector<BYTE> der(size);
    if (!CryptStringToBinaryA(pem.data(), static_cast<DWORD>(pem.size()), flags, der.data(), &size, nullptr, nullptr)) return false;
    result.value = CertCreateCertificateContext(X509_ASN_ENCODING, der.data(), size);
    return result.value != nullptr;
}

bool set_dword(HINTERNET handle, DWORD option, DWORD value) {
    return WinHttpSetOption(handle, option, &value, sizeof(value)) != FALSE;
}

bool authentic_server(HINTERNET request, const certificate& pin) {
    certificate peer;
    DWORD size = sizeof(peer.value);
    if (!WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &peer.value, &size) ||
        size != sizeof(peer.value) || !peer.value ||
        CertVerifyTimeValidity(nullptr, peer.value->pCertInfo) != 0) return false;
    // WinHTTP has already checked hostname, validity, server usage, and the
    // chain. For a supplied pin ONLY unknown-CA is tolerated; exact leaf DER
    // equality replaces CA trust before any secret body bytes can be written.
    return !pin.value || (peer.value->cbCertEncoded == pin.value->cbCertEncoded &&
        std::memcmp(peer.value->pbCertEncoded, pin.value->pbCertEncoded, peer.value->cbCertEncoded) == 0);
}

bool positive_integer(const ohno_json::value& field, std::int64_t& result) {
    if (field.type != ohno_json::value::kind::number || field.text.empty() || field.text.size() > 12) return false;
    result = 0;
    for (char ch : field.text) {
        if (ch < '0' || ch > '9') return false;
        result = result * 10 + (ch - '0');
    }
    return result > 0;
}

bool authorized_response(const std::string& body, const ohno::MaintenanceRequest& request) {
    const auto parsed = ohno_json::parse(body);
    if (parsed.type != ohno_json::value::kind::object || parsed.fields.size() != 6) return false;
    const auto& allowed = parsed.at("authorized");
    if (allowed.type != ohno_json::value::kind::boolean || !allowed.boolean) return false;
    const auto matches = [&parsed](const char* name, const std::string& expected) {
        const auto& field = parsed.at(name);
        return field.type == ohno_json::value::kind::string && field.text == expected;
    };
    if (!matches("action", request.action) || !matches("nonce", request.nonce) ||
        !matches("device_id", request.device_id)) return false;
    std::int64_t issued = 0, expires = 0;
    if (!positive_integer(parsed.at("authorized_at"), issued) ||
        !positive_integer(parsed.at("expires_at"), expires) || expires - issued != 120) return false;
    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    // This is a fresh nonce-bound online response, not a reusable ticket.
    // Allow only 30 seconds of teacher/client clock skew; the independent
    // monotonic 20-second request deadline prevents holding/reusing a response.
    return now > 0 && issued <= now + 30 && now < expires + 30;
}

bool json_content_type(HINTERNET request) {
    wchar_t value[128]{};
    DWORD size = sizeof(value);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX,
                             value, &size, WINHTTP_NO_HEADER_INDEX)) return false;
    std::wstring type(value);
    std::transform(type.begin(), type.end(), type.begin(), [](wchar_t ch) {
        return ch >= L'A' && ch <= L'Z' ? static_cast<wchar_t>(ch - L'A' + L'a') : ch;
    });
    const auto delimiter = type.find(L';');
    type.resize(delimiter == std::wstring::npos ? type.size() : delimiter);
    while (!type.empty() && (type.back() == L' ' || type.back() == L'\t')) type.pop_back();
    return type == L"application/json";
}

bool unencoded_body(HINTERNET request) {
    wchar_t value[32]{};
    DWORD size = sizeof(value);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_ENCODING, WINHTTP_HEADER_NAME_BY_INDEX,
            value, &size, WINHTTP_NO_HEADER_INDEX)) return GetLastError() == ERROR_WINHTTP_HEADER_NOT_FOUND;
    return _wcsicmp(value, L"identity") == 0;
}
}

namespace ohno {
MaintenanceResult authorize_maintenance(const MaintenanceRequest& input) noexcept {
    try {
        if ((input.action != "install" && input.action != "uninstall") ||
            !lower_hex(input.nonce, 64) || !valid_password(input.password) ||
            (input.action == "install" && (!input.device_id.empty() || !input.device_key.empty())) ||
            (input.action == "uninstall" && (!lower_hex(input.device_id, 32) || !lower_hex(input.device_key, 64))))
            return MaintenanceResult::InvalidResponse;
        std::wstring host;
        INTERNET_PORT port = 0;
        if (!parse_origin(input.server, host, port)) return MaintenanceResult::InvalidResponse;
        certificate pin;
        if (!input.certificate_pem.empty() && !parse_pin(input.certificate_pem, pin)) return MaintenanceResult::InvalidResponse;

        secret_body body;
        body.value.reserve(max_body); // no reallocations leaving stale secret copies
        body.value = "{\"action\":";
        append_quoted(body.value, input.action);
        body.value += ",\"nonce\":";
        append_quoted(body.value, input.nonce);
        body.value += ",\"maintenance_password\":";
        append_quoted(body.value, input.password);
        if (input.action == "uninstall") {
            body.value += ",\"device_id\":";
            append_quoted(body.value, input.device_id);
            body.value += ",\"device_key\":";
            append_quoted(body.value, input.device_key);
        }
        body.value += '}';
        if (body.value.size() > max_body) return MaintenanceResult::InvalidResponse;

        const auto started = GetTickCount64();
        // Direct LAN connection: do not consult proxy/PAC configuration, share
        // browser cookies, send integrated Windows credentials, or mutate trust.
        http_handle session(WinHttpOpen(L"ohno-maintenance/1", WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
        if (!session.value || !WinHttpSetTimeouts(session.value, 5000, 5000, 5000, 5000) ||
            !set_dword(session.value, WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2) ||
            // At most two addresses of this same host (e.g. localhost ::1 then
            // 127.0.0.1), before TLS/authentication/body transmission. This is
            // not an HTTP replay, and never changes the configured origin.
            !set_dword(session.value, WINHTTP_OPTION_CONNECT_RETRIES, 2) ||
            !set_dword(session.value, WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE, 8192)) return MaintenanceResult::Unavailable;
        http_handle connection(WinHttpConnect(session.value, host.c_str(), port, 0));
        if (!connection.value) return MaintenanceResult::Unavailable;
        const wchar_t* accept[] = {L"application/json", nullptr};
        http_handle request(WinHttpOpenRequest(connection.value, L"POST", L"/api/maintenance/authorize",
            L"HTTP/1.1", WINHTTP_NO_REFERER, accept, WINHTTP_FLAG_SECURE));
        if (!request.value ||
            !set_dword(request.value, WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_DISABLE_REDIRECTS |
                WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_KEEP_ALIVE) ||
            !set_dword(request.value, WINHTTP_OPTION_AUTOLOGON_POLICY, WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH) ||
            !WinHttpSetOption(request.value, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT, 0))
            return MaintenanceResult::Unavailable;
        if (pin.value && !set_dword(request.value, WINHTTP_OPTION_SECURITY_FLAGS, SECURITY_FLAG_IGNORE_UNKNOWN_CA))
            return MaintenanceResult::Unavailable;

        // CRITICAL: WinHttpSendRequest performs TLS and sends ONLY non-secret
        // headers. Its optional-body pointer and length MUST remain null/zero.
        // Microsoft documents dwTotalLength > dwOptionalLength followed by
        // WinHttpWriteData; SERVER_CERT_CONTEXT is from this negotiated request.
        // https://learn.microsoft.com/windows/win32/api/winhttp/nf-winhttp-winhttpsendrequest
        // https://learn.microsoft.com/windows/win32/winhttp/option-flags
        constexpr wchar_t headers[] = L"Content-Type: application/json\r\nCache-Control: no-store\r\n";
        if (!WinHttpSendRequest(request.value, headers, static_cast<DWORD>(-1L), WINHTTP_NO_REQUEST_DATA,
                0, static_cast<DWORD>(body.value.size()), 0) ||
            !authentic_server(request.value, pin) || GetTickCount64() - started > total_timeout_ms)
            return MaintenanceResult::Unavailable;
        DWORD written = 0;
        // No retry, even for ERROR_WINHTTP_RESEND_REQUEST. No secret is ever
        // supplied as optional data that WinHTTP could replay during redirects.
        if (!WinHttpWriteData(request.value, body.value.data(), static_cast<DWORD>(body.value.size()), &written) ||
            written != body.value.size() || !WinHttpReceiveResponse(request.value, nullptr) ||
            GetTickCount64() - started > total_timeout_ms) return MaintenanceResult::Unavailable;
        DWORD status = 0, size = sizeof(status);
        if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) return MaintenanceResult::Unavailable;
        if (status == 403) return MaintenanceResult::Denied;
        if (status == 503) return MaintenanceResult::Unavailable;
        if (status != 200 || !json_content_type(request.value) || !unencoded_body(request.value)) return MaintenanceResult::InvalidResponse;
        DWORD expected = 0;
        size = sizeof(expected);
        const bool has_length = WinHttpQueryHeaders(request.value, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &expected, &size, WINHTTP_NO_HEADER_INDEX) != FALSE;
        if ((!has_length && GetLastError() != ERROR_WINHTTP_HEADER_NOT_FOUND) ||
            (has_length && expected > max_body)) return MaintenanceResult::InvalidResponse;
        std::string response;
        response.reserve(max_body);
        for (;;) {
            if (GetTickCount64() - started > total_timeout_ms) return MaintenanceResult::Unavailable;
            char buffer[512]{};
            DWORD count = 0;
            if (!WinHttpReadData(request.value, buffer, sizeof(buffer), &count)) return MaintenanceResult::Unavailable;
            if (response.size() + count > max_body) return MaintenanceResult::InvalidResponse;
            if (count == 0) break;
            response.append(buffer, count);
        }
        if ((has_length && response.size() != expected) || GetTickCount64() - started > total_timeout_ms)
            return MaintenanceResult::InvalidResponse;
        return authorized_response(response, input) ? MaintenanceResult::Authorized : MaintenanceResult::InvalidResponse;
    } catch (...) {
        // Parser/encoding/allocation errors are never authorizations. In
        // particular, do not include attacker-controlled bodies or credentials
        // in diagnostics, exception text, files, or event/debug logs.
        return MaintenanceResult::InvalidResponse;
    }
}
}
