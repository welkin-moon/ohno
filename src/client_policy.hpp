#pragma once
#include "feature_match.hpp"
#include "json.hpp"
#include "policy.hpp"
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace ohno {
struct TemporaryGrant {
    std::string kind;
    std::string object;
    std::int64_t expires;
};

struct ClientPolicy {
    PolicyMode web_mode = PolicyMode::Blacklist;
    PolicyMode program_mode = PolicyMode::Blacklist;
    std::vector<std::string> domains, allow_domains;
    std::vector<std::string> hashes, names, features;
    std::vector<std::string> allow_hashes, allow_names, allow_features;
    bool block_local_files = false;
    std::vector<TemporaryGrant> grants;
};

inline bool valid_program_name(const std::string& name) {
    if (name.size() < 5 || name.size() > 132 || name.compare(name.size()-4, 4, ".exe") != 0)
        return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '.' || c == ' ' || c == '-' || c == '+';
    });
}

inline std::int64_t policy_integer(const ohno_json::value& value) {
    if (value.type != ohno_json::value::kind::number || value.text.empty() ||
        value.text.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("invalid policy integer");
    return std::stoll(value.text);
}

inline PolicyMode parse_policy_mode(const ohno_json::value& object, const char* key) {
    auto it = object.fields.find(key);
    if (it == object.fields.end()) return PolicyMode::Blacklist;
    if (it->second.type != ohno_json::value::kind::string)
        throw std::runtime_error("invalid policy mode");
    if (it->second.text == "blacklist") return PolicyMode::Blacklist;
    if (it->second.text == "whitelist") return PolicyMode::Whitelist;
    throw std::runtime_error("unknown policy mode");
}

// Decode the complete payload before it can replace the last usable cache or
// alter any OS rules. Dropping malformed array entries could weaken a policy.
inline ClientPolicy parse_client_policy(const ohno_json::value& value) {
    ClientPolicy result;
    policy_integer(value.at("revision"));
    const auto& local = value.at("block_local_files");
    if (local.type != ohno_json::value::kind::boolean)
        throw std::runtime_error("invalid local file policy");
    result.block_local_files = local.boolean;
    result.web_mode = parse_policy_mode(value, "web_mode");
    result.program_mode = parse_policy_mode(value, "program_mode");

    auto parse_list = [&](const char* key, bool (*valid)(const std::string&), bool required) {
        auto it = value.fields.find(key);
        if (it == value.fields.end()) {
            if (required) throw std::runtime_error("missing required policy array");
            return std::vector<std::string>{};
        }
        const auto& array = it->second;
        if (array.type != ohno_json::value::kind::array || array.items.size() > 1000)
            throw std::runtime_error("invalid policy array");
        std::vector<std::string> values;
        values.reserve(array.items.size());
        for (const auto& item : array.items) {
            if (item.type != ohno_json::value::kind::string || !valid(item.text))
                throw std::runtime_error("invalid policy rule");
            values.push_back(item.text);
        }
        return values;
    };

    result.domains = parse_list("web_domains", valid_hostname, true);
    result.allow_domains = parse_list("allow_web_domains", valid_hostname, false);
    result.hashes = parse_list("program_hashes", valid_sha256, true);
    result.names = parse_list("program_names", valid_program_name, true);
    result.features = parse_list("program_features", valid_feature_rule, false);
    result.allow_hashes = parse_list("allow_program_hashes", valid_sha256, false);
    result.allow_names = parse_list("allow_program_names", valid_program_name, false);
    result.allow_features = parse_list("allow_program_features", valid_feature_rule, false);

    if (result.domains.size() + (local.boolean ? 1u : 0u) > 1000)
        throw std::runtime_error("too many browser rules");
    if (result.allow_domains.size() > 950)
        throw std::runtime_error("too many allowed browser rules");

    const auto& grants = value.at("grants");
    if (grants.type != ohno_json::value::kind::array || grants.items.size() > 10000)
        throw std::runtime_error("invalid grants");
    for (const auto& grant : grants.items) {
        const auto& kind = grant.at("kind");
        const auto& object = grant.at("object");
        if (kind.type != ohno_json::value::kind::string ||
            object.type != ohno_json::value::kind::string)
            throw std::runtime_error("invalid grant identity");
        const auto& k = kind.text;
        const auto& obj = object.text;
        const bool local_html = k == "local_html" && !obj.empty() &&
            std::count_if(obj.begin(), obj.end(), [](unsigned char c) { return (c & 0xc0) != 0x80; }) <= 512 &&
            std::none_of(obj.begin(), obj.end(), [](unsigned char c) { return c < 32 || c == 127; });
        if (!((k == "website" && valid_hostname(obj)) ||
              ((k == "application" || k == "network") && valid_sha256(obj)) ||
              (k == "pause" && obj == "*") || local_html))
            throw std::runtime_error("invalid grant object");
        result.grants.push_back({k, obj, policy_integer(grant.at("expires"))});
    }
    return result;
}

struct EffectivePolicy {
    PolicyMode web_mode = PolicyMode::Blacklist;
    PolicyMode program_mode = PolicyMode::Blacklist;
    std::vector<std::string> domains;         // Edge URLBlocklist (or TUN block suffixes in blacklist mode)
    std::vector<std::string> tun_domains;     // Blocked suffixes (blacklist) or allowed suffixes (whitelist)
    std::vector<std::string> hashes, names, features;
    std::vector<std::string> allow_hashes, allow_names, allow_features;
    std::vector<std::string> allowed_programs, allowed_network, allowed_sites;
    bool paused = false;

    ProcessRuleSet process_rules() const {
        return ProcessRuleSet{
            program_mode,
            hashes, names, features,
            allow_hashes, allow_names, allow_features,
            allowed_programs
        };
    }
};

inline EffectivePolicy effective_policy(const ClientPolicy& policy, std::int64_t now, bool online) {
    EffectivePolicy result;
    result.web_mode = policy.web_mode;
    result.program_mode = policy.program_mode;
    result.hashes = policy.hashes;
    result.names = policy.names;
    result.features = policy.features;
    result.allow_hashes = policy.allow_hashes;
    result.allow_names = policy.allow_names;
    result.allow_features = policy.allow_features;

    if (policy.web_mode == PolicyMode::Whitelist) {
        result.domains.push_back("*");
        if (policy.block_local_files) result.domains.push_back("file://*");
        result.tun_domains = policy.allow_domains;
        result.allowed_sites = policy.allow_domains;
    } else {
        result.domains = policy.domains;
        result.tun_domains = policy.domains;
        if (policy.block_local_files) result.domains.push_back("file://*");
    }

    if (online) for (const auto& grant : policy.grants) {
        if (grant.expires <= now) continue;
        if (grant.kind == "application") result.allowed_programs.push_back(grant.object);
        else if (grant.kind == "network") result.allowed_network.push_back(grant.object);
        else if (grant.kind == "website") result.allowed_sites.push_back("." + grant.object);
        else if (grant.kind == "pause") result.paused = true;
    }
    if (result.paused) {
        result.web_mode = PolicyMode::Blacklist;
        result.domains.clear();
        result.tun_domains.clear();
    }
    return result;
}
}
