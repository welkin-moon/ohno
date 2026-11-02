#pragma once
#include "json.hpp"
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace ohno {
constexpr std::uint64_t max_update_sequence = 9007199254740991ULL;
constexpr std::uint64_t max_update_timestamp = 253402300799ULL;
constexpr std::uint64_t max_update_package_size = 256ULL * 1024 * 1024;
struct UpdateManifest {
    std::uint64_t sequence = 0, min_updater = 0, issued_at = 0, expires_at = 0, size = 0;
    std::string version, sha256, signature;
};
namespace update_detail {
inline bool lower_hex(const std::string& text, std::size_t size) {
    if (text.size() != size) return false;
    for (char c : text) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
inline std::string text(const ohno_json::value& object, const char* field) {
    const auto& value = object.at(field);
    if (value.type != ohno_json::value::kind::string) throw std::runtime_error("invalid update string");
    return value.text;
}
inline std::uint64_t integer(const ohno_json::value& object, const char* field,
                             std::uint64_t low, std::uint64_t high) {
    const auto& value = object.at(field);
    if (value.type != ohno_json::value::kind::number || value.text.empty()) throw std::runtime_error("invalid update integer");
    std::uint64_t n = 0;
    for (char c : value.text) {
        if (c < '0' || c > '9' || n > high / 10 ||
            (n == high / 10 && static_cast<unsigned>(c - '0') > high % 10))
            throw std::runtime_error("update integer outside limits");
        n = n * 10 + static_cast<unsigned>(c - '0');
    }
    if (n < low || n > high) throw std::runtime_error("update integer outside limits");
    return n;
}
inline bool version(const std::string& value) {
    std::size_t i = 0;
    for (int part = 0; part < 3; ++part) {
        const auto start = i;
        while (i < value.size() && value[i] >= '0' && value[i] <= '9') ++i;
        const auto count = i - start;
        if (count == 0 || count > 6 || (count > 1 && value[start] == '0')) return false;
        if (part < 2 && (i == value.size() || value[i++] != '.')) return false;
    }
    if (i == value.size()) return true;
    if (value[i++] != '-' || i == value.size() || value.size() - i > 32) return false;
    auto alnum = [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); };
    if (!alnum(value[i])) return false;
    for (; i < value.size(); ++i) if (!alnum(value[i]) && value[i] != '.' && value[i] != '-') return false;
    return true;
}
}
// Parsing is not authentication. Runtime callers use verify_update_offer(),
// which also verifies the pinned key, replay floor and time/version constraints.
inline UpdateManifest parse_update_manifest(const std::string& document) {
    if (document.size() > 4096) throw std::runtime_error("update document too large");
    auto object = ohno_json::parse(document);
    if (object.type != ohno_json::value::kind::object || object.fields.size() != 10)
        throw std::runtime_error("unknown or missing update fields");
    if (update_detail::integer(object, "schema", 1, 1) != 1 ||
        update_detail::text(object, "platform") != "windows-x64")
        throw std::runtime_error("unsupported update schema or platform");
    UpdateManifest manifest;
    manifest.sequence = update_detail::integer(object, "sequence", 1, max_update_sequence);
    manifest.version = update_detail::text(object, "version");
    manifest.min_updater = update_detail::integer(object, "min_updater", 1, 65535);
    manifest.issued_at = update_detail::integer(object, "issued_at", 1, max_update_timestamp);
    manifest.expires_at = update_detail::integer(object, "expires_at", 1, max_update_timestamp);
    manifest.size = update_detail::integer(object, "size", 1024, max_update_package_size);
    manifest.sha256 = update_detail::text(object, "sha256");
    manifest.signature = update_detail::text(object, "signature");
    if (!update_detail::version(manifest.version) ||
        !update_detail::lower_hex(manifest.sha256, 64) || !update_detail::lower_hex(manifest.signature, 128) ||
        manifest.expires_at <= manifest.issued_at || manifest.expires_at - manifest.issued_at > 7 * 24 * 3600)
        throw std::runtime_error("invalid update identity or validity interval");
    return manifest;
}
inline std::string update_signing_bytes(const UpdateManifest& manifest) {
    return "ohno-update-p256-sha256-v1\n1\nwindows-x64\n" + std::to_string(manifest.sequence) + "\n" +
        manifest.version + "\n" + std::to_string(manifest.min_updater) + "\n" +
        std::to_string(manifest.issued_at) + "\n" + std::to_string(manifest.expires_at) + "\n" +
        std::to_string(manifest.size) + "\n" + manifest.sha256 + "\n";
}
inline void require_new_update(const UpdateManifest& manifest, std::uint64_t installed_sequence,
                               std::uint64_t updater_version, std::uint64_t now) {
    if (installed_sequence > max_update_sequence || updater_version == 0 || updater_version > 65535 ||
        now == 0 || now > max_update_timestamp) throw std::runtime_error("invalid trusted update context");
    if (manifest.sequence <= installed_sequence) throw std::runtime_error("replayed update sequence");
    if (manifest.min_updater > updater_version) throw std::runtime_error("updater is too old");
    if (manifest.issued_at > now + 300 || manifest.expires_at <= now)
        throw std::runtime_error("update expired or not yet valid");
}
inline std::string update_package_path(const UpdateManifest& manifest) {
    if (!update_detail::lower_hex(manifest.sha256, 64)) throw std::runtime_error("invalid package hash");
    return "/api/device/update/package/" + manifest.sha256;
}
}
