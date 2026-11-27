#pragma once
#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace ohno {

enum class PolicyMode { Blacklist, Whitelist };

struct ProcessFeatures {
    std::string exe_name;         // basename, e.g. "word.exe"
    std::string full_path;        // full UTF-8 path
    std::string orig_filename;    // PE VersionInfo OriginalFilename
    std::string product_name;     // PE VersionInfo ProductName
    std::string file_description; // PE VersionInfo FileDescription
    std::string company_name;     // PE VersionInfo CompanyName
    std::string internal_name;    // PE VersionInfo InternalName
    std::string signer;           // Authenticode certificate subject / publisher
    std::string window_title;     // visible top-level window title(s)
};

struct ProcessRuleSet {
    PolicyMode mode = PolicyMode::Blacklist;
    std::vector<std::string> block_hashes;
    std::vector<std::string> block_names;
    std::vector<std::string> block_features;
    std::vector<std::string> allow_hashes;
    std::vector<std::string> allow_names;
    std::vector<std::string> allow_features;
    std::vector<std::string> temp_allowed_hashes;
};

inline std::string ascii_lower(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        out.push_back(c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c));
    }
    return out;
}

inline bool contains_icase(std::string_view haystack, std::string_view needle) {
    if (needle.empty() || haystack.empty()) return false;
    const auto h = ascii_lower(haystack);
    const auto n = ascii_lower(needle);
    return h.find(n) != std::string::npos;
}

inline bool equals_icase(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        unsigned char ca = static_cast<unsigned char>(a[i]);
        unsigned char cb = static_cast<unsigned char>(b[i]);
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

// Validate a UTF-8 feature rule: optional prefix (any/orig/product/company/desc/signer/title/path)
// followed by a non-empty printable keyword (total <= 160 bytes, no control chars).
inline bool valid_feature_rule(const std::string& rule) {
    if (rule.empty() || rule.size() > 160) return false;
    for (unsigned char c : rule) {
        if (c < 32 || c == 127) return false;
    }
    std::string_view body = rule;
    const auto colon = body.find(':');
    if (colon != std::string_view::npos) {
        const auto prefix = body.substr(0, colon);
        if (prefix == "any" || prefix == "orig" || prefix == "product" || prefix == "company" ||
            prefix == "desc" || prefix == "signer" || prefix == "title" || prefix == "path") {
            body = body.substr(colon + 1);
        } else {
            return false;
        }
    }
    // Trim check: keyword must not be empty or whitespace-only.
    return std::any_of(body.begin(), body.end(), [](unsigned char c) { return c > 32; });
}

inline bool matches_feature_rule(const ProcessFeatures& f, const std::string& rule) {
    if (!valid_feature_rule(rule)) return false;
    std::string_view prefix = "any";
    std::string_view keyword = rule;
    const auto colon = keyword.find(':');
    if (colon != std::string_view::npos) {
        prefix = keyword.substr(0, colon);
        keyword = keyword.substr(colon + 1);
    }
    if (prefix == "orig") {
        return contains_icase(f.orig_filename, keyword) || contains_icase(f.internal_name, keyword);
    }
    if (prefix == "product") return contains_icase(f.product_name, keyword);
    if (prefix == "company") return contains_icase(f.company_name, keyword);
    if (prefix == "desc") return contains_icase(f.file_description, keyword);
    if (prefix == "signer") return contains_icase(f.signer, keyword);
    if (prefix == "title") return contains_icase(f.window_title, keyword);
    if (prefix == "path") return contains_icase(f.full_path, keyword);
    // "any": matches across all metadata fields, signer, title, and executable name.
    return contains_icase(f.exe_name, keyword) ||
           contains_icase(f.orig_filename, keyword) ||
           contains_icase(f.internal_name, keyword) ||
           contains_icase(f.product_name, keyword) ||
           contains_icase(f.file_description, keyword) ||
           contains_icase(f.company_name, keyword) ||
           contains_icase(f.signer, keyword) ||
           contains_icase(f.window_title, keyword);
}

inline bool matches_any_name(const std::string& exe_name, const std::vector<std::string>& names) {
    if (exe_name.empty()) return false;
    for (const auto& n : names) {
        if (equals_icase(exe_name, n)) return true;
    }
    return false;
}

inline bool matches_any_hash(const std::string& hash, const std::vector<std::string>& hashes) {
    if (hash.empty()) return false;
    return std::find(hashes.begin(), hashes.end(), hash) != hashes.end();
}

inline bool matches_any_feature(const ProcessFeatures& f, const std::vector<std::string>& features) {
    for (const auto& rule : features) {
        if (matches_feature_rule(f, rule)) return true;
    }
    return false;
}

// Evaluates whether a process should be terminated under Blacklist or Whitelist mode.
// Protected OS / Ohno / Session-0 service processes are never terminated.
inline bool should_block_process(const ProcessRuleSet& rules,
                                 const ProcessFeatures& features,
                                 const std::string& hash,
                                 bool protected_process) {
    if (protected_process) return false;
    if (matches_any_hash(hash, rules.temp_allowed_hashes)) return false;

    if (rules.mode == PolicyMode::Whitelist) {
        // Explicit allowlist check: hash, filename, or feature match permits execution.
        if (matches_any_hash(hash, rules.allow_hashes)) return false;
        if (matches_any_name(features.exe_name, rules.allow_names)) return false;
        if (matches_any_feature(features, rules.allow_features)) return false;
        return true;
    }

    // Blacklist mode: block when any hash, filename, or feature rule matches.
    if (matches_any_hash(hash, rules.block_hashes)) return true;
    if (matches_any_name(features.exe_name, rules.block_names)) return true;
    if (matches_any_feature(features, rules.block_features)) return true;
    return false;
}

} // namespace ohno
