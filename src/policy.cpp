#include "policy.hpp"

namespace ohno {
bool valid_sha256(const std::string& s) {
    if (s.size() != 64) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
bool valid_hostname(const std::string& host) {
    if (host.empty() || host.size() > 253 || host.front() == '.' || host.back() == '.') return false;
    std::size_t label = 0;
    for (std::size_t i = 0; i < host.size(); ++i) {
        const unsigned char c = host[i];
        if (c == '.') {
            if (label == 0 || label > 63 || host[i-1] == '-') return false;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
            if (label == 0 && c == '-') return false;
            ++label;
        }
    }
    return label > 0 && label <= 63 && host.back() != '-';
}
static bool matches_domain(const std::string& hostname, const Rule& rule) {
    if (hostname == rule.value) return true;
    return rule.include_subdomains && hostname.size() > rule.value.size() &&
        hostname.compare(hostname.size() - rule.value.size(), rule.value.size(), rule.value) == 0 &&
        hostname[hostname.size() - rule.value.size() - 1] == '.';
}
Decision evaluate(const Request& request, const std::vector<Rule>& rules,
                  const std::vector<Grant>& grants, std::int64_t now) {
    if (request.machine.empty() || request.user.empty())
        return {Action::Block, "missing trusted machine or user identity", ""};
    if ((request.kind == Kind::Application || request.kind == Kind::Network) && !valid_sha256(request.object))
        return {Action::Block, "invalid executable SHA-256", ""};
    if (request.kind == Kind::Website && !valid_hostname(request.object))
        return {Action::Block, "invalid or noncanonical hostname", ""};
    if (request.kind == Kind::LocalHtml && request.object.empty())
        return {Action::Block, "missing local resource identity", ""};

    // Grants are scoped and expire. In production their authenticity, machine
    // enrollment, revocation, and replay protection are mandatory OS-side work.
    const bool granted = std::any_of(grants.begin(), grants.end(), [&](const Grant& g) {
        return g.kind == request.kind && g.machine == request.machine && g.user == request.user &&
               g.object == request.object && now < g.expires_at;
    });
    for (const auto& rule : rules) {
        if (rule.kind != request.kind) continue;
        bool matched = request.kind == Kind::Website ? valid_hostname(rule.value) && matches_domain(request.object, rule)
                     : request.kind == Kind::LocalHtml ? rule.value == "*"
                     : valid_sha256(rule.value) && request.object == rule.value;
        if (matched) return granted ? Decision{Action::Allow, "teacher grant", rule.id}
                                    : Decision{Action::RequestApproval, "blocked by rule", rule.id};
    }
    if (request.kind == Kind::Network && request.origin != Origin::Managed)
        return granted ? Decision{Action::Allow, "teacher grant", "origin"}
                       : Decision{Action::RequestApproval, "untrusted or unknown origin", "origin"};
    return {Action::Allow, "no matching restriction", ""};
}
const char* to_string(Action a) {
    switch (a) { case Action::Allow: return "ALLOW"; case Action::Block: return "BLOCK"; case Action::RequestApproval: return "REQUEST_APPROVAL"; }
    return "BLOCK";
}
}
