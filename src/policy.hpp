#pragma once
#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ohno {
enum class Action { Allow, Block, RequestApproval };
enum class Kind { Website, Application, Network, LocalHtml };
enum class Origin { Managed, Downloaded, Removable, Unknown };
struct Rule {
    std::string id;
    Kind kind;
    std::string value; // domain or SHA-256 for this illustrative policy core
    bool include_subdomains = false;
};
struct Request {
    Kind kind;
    std::string machine;
    std::string user;
    std::string object; // canonical hostname or SHA-256; see interface contract
    Origin origin = Origin::Unknown;
};
struct Grant {
    Kind kind;
    std::string machine;
    std::string user;
    std::string object;
    std::int64_t expires_at;
};
struct Decision {
    Action action;
    std::string reason;
    std::string rule_id;
};

// The caller must provide normalized identity and object values from trusted OS
// sources; this function does not authenticate requests, verify hashes or apply
// rules to the operating system. "Unknown" provenance is deliberately gated.
Decision evaluate(const Request&, const std::vector<Rule>&,
                  const std::vector<Grant>&, std::int64_t now);
bool valid_sha256(const std::string&);
bool valid_hostname(const std::string&);
const char* to_string(Action);
}
