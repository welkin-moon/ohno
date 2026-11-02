#pragma once
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
    std::vector<std::string> domains, hashes, names;
    bool block_local_files = false;
    std::vector<TemporaryGrant> grants;
};

inline bool valid_program_name(const std::string& name) {
    if (name.size() < 5 || name.size() > 132 || name.compare(name.size()-4, 4, ".exe") != 0)
        return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '.' || c == ' ' || c == '-';
    });
}

inline std::int64_t policy_integer(const ohno_json::value& value) {
    if (value.type != ohno_json::value::kind::number || value.text.empty() ||
        value.text.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("invalid policy integer");
    return std::stoll(value.text);
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
    auto strings = [&](const char* key, bool (*valid)(const std::string&)) {
        const auto& array = value.at(key);
        if (array.type != ohno_json::value::kind::array || array.items.size() > 1000)
            throw std::runtime_error("invalid policy array");
        std::vector<std::string> values;
        for (const auto& item : array.items) {
            if (item.type != ohno_json::value::kind::string || !valid(item.text))
                throw std::runtime_error("invalid policy rule");
            values.push_back(item.text);
        }
        return values;
    };
    result.domains = strings("web_domains", valid_hostname);
    result.hashes = strings("program_hashes", valid_sha256);
    result.names = strings("program_names", valid_program_name);
    if (result.domains.size() + (local.boolean ? 1u : 0u) > 1000)
        throw std::runtime_error("too many browser rules");
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
    std::vector<std::string> domains, hashes, names;
    std::vector<std::string> allowed_programs, allowed_network, allowed_sites;
    bool paused = false;
};

inline EffectivePolicy effective_policy(const ClientPolicy& policy, std::int64_t now, bool online) {
    EffectivePolicy result;
    result.domains = policy.domains;
    result.hashes = policy.hashes;
    result.names = policy.names;
    if (policy.block_local_files) result.domains.push_back("file://*");
    if (online) for (const auto& grant : policy.grants) {
        if (grant.expires <= now) continue;
        if (grant.kind == "application") result.allowed_programs.push_back(grant.object);
        else if (grant.kind == "network") result.allowed_network.push_back(grant.object);
        else if (grant.kind == "website") result.allowed_sites.push_back("." + grant.object);
        else if (grant.kind == "pause") result.paused = true;
    }
    if (result.paused) result.domains.clear();
    return result;
}
}
