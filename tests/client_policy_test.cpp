#include "client_policy.hpp"
#include <cassert>
#include <iostream>

using ohno_json::parse;
const std::string base = R"({"revision":1,"web_domains":["game.example"],"program_hashes":[],"program_names":["game.exe"],"block_local_files":true,"grants":[]})";

int main() {
    auto input = parse(base);
    const std::string hash(64, 'a');
    input.fields["grants"] = parse("[{\"kind\":\"application\",\"object\":\""+hash+
        "\",\"expires\":200},{\"kind\":\"website\",\"object\":\"game.example\",\"expires\":200}]");
    auto policy = ohno::parse_client_policy(input);
    auto active = ohno::effective_policy(policy, 100, true);
    assert(active.domains.size() == 2 && active.names[0] == "game.exe");
    assert(active.allowed_programs == std::vector<std::string>{hash});
    assert(active.allowed_sites == std::vector<std::string>{".game.example"});
    for (auto online : {true, false}) {
        auto expired = ohno::effective_policy(policy, 200, online);
        assert(expired.allowed_programs.empty() && expired.allowed_sites.empty());
    }
    auto offline = ohno::effective_policy(policy, 100, false);
    assert(offline.allowed_programs.empty() && offline.allowed_sites.empty());
    policy.grants.push_back({"pause", "*", 200});
    assert(ohno::effective_policy(policy, 100, true).domains.empty());
    assert(!ohno::effective_policy(policy, 100, false).paused);
    assert(!ohno::effective_policy(policy, 200, true).paused);

    auto rejects = [](const ohno_json::value& invalid) {
        bool rejected = false;
        try { ohno::parse_client_policy(invalid); } catch (const std::exception&) { rejected = true; }
        assert(rejected);
    };
    for (const auto& pair : std::vector<std::pair<std::string, std::string>>{
            {"revision", "-1"}, {"revision", "1.0"},
            {"web_domains", "[\"valid.example\", 3]"},
            {"web_domains", "[\"bad domain\"]"},
            {"program_hashes", "[\"short\"]"}, {"program_names", "[\"path/game.exe\"]"},
            {"block_local_files", "1"}, {"grants", "[{}]"},
            {"grants", "[{\"kind\":\"pause\",\"object\":\"other\",\"expires\":200}]"},
            {"grants", "[{\"kind\":\"pause\",\"object\":\"*\",\"expires\":2e2}]"},
            {"grants", "[{\"kind\":\"pause\",\"object\":\"*\",\"expires\":99999999999999999999}]"}}) {
        auto invalid = parse(base);
        invalid.fields[pair.first] = parse(pair.second);
        rejects(invalid);
    }
    auto oversized = parse(base);
    oversized.fields["web_domains"].items.resize(1000, parse("\"game.example\""));
    rejects(oversized); // local-file rule also consumes an Edge policy slot
    oversized.fields["block_local_files"].boolean = false;
    ohno::parse_client_policy(oversized);
    oversized.fields["web_domains"].items.push_back(parse("\"extra.example\""));
    rejects(oversized);

    // Dual-mode (whitelist) and executable feature rule validation.
    const std::string dual_json = R"({
        "revision": 2,
        "web_mode": "whitelist",
        "web_domains": ["game.example"],
        "allow_web_domains": ["edu.cn", "wikipedia.org"],
        "program_mode": "whitelist",
        "program_hashes": [],
        "program_names": ["game.exe"],
        "program_features": ["orig:plantsvszombies.exe", "title:植物大战僵尸"],
        "allow_program_hashes": [")" + hash + R"("],
        "allow_program_names": ["msedge.exe"],
        "allow_program_features": ["signer:microsoft corporation"],
        "block_local_files": true,
        "grants": [{"kind":"website","object":"docs.python.org","expires":200}]
    })";
    auto dual = ohno::parse_client_policy(parse(dual_json));
    assert(dual.web_mode == ohno::PolicyMode::Whitelist);
    assert(dual.program_mode == ohno::PolicyMode::Whitelist);
    auto dual_active = ohno::effective_policy(dual, 100, true);
    assert(dual_active.web_mode == ohno::PolicyMode::Whitelist);
    assert(dual_active.domains.size() == 2 && dual_active.domains[0] == "*" && dual_active.domains[1] == "file://*");
    assert(dual_active.tun_domains.size() == 2 && dual_active.tun_domains[0] == "edu.cn");
    assert(dual_active.allowed_sites.size() == 3 && dual_active.allowed_sites[2] == ".docs.python.org");
    auto rules = dual_active.process_rules();
    assert(rules.mode == ohno::PolicyMode::Whitelist);
    assert(rules.allow_features.size() == 1 && rules.allow_features[0] == "signer:microsoft corporation");

    // Pause overrides whitelist web blocking.
    dual.grants.push_back({"pause", "*", 200});
    auto dual_paused = ohno::effective_policy(dual, 100, true);
    assert(dual_paused.paused && dual_paused.web_mode == ohno::PolicyMode::Blacklist);
    assert(dual_paused.domains.empty() && dual_paused.tun_domains.empty());

    // Invalid modes and feature prefixes are rejected.
    for (const auto& pair : std::vector<std::pair<std::string, std::string>>{
            {"web_mode", "\"invalid\""},
            {"program_mode", "\"other\""},
            {"program_features", "[\"badprefix:foo\"]"},
            {"allow_program_features", "[\"orig:   \"]"},
            {"allow_web_domains", "[\"bad domain\"]"},
            {"allow_program_names", "[\"notexe.txt\"]"}}) {
        auto invalid = parse(dual_json);
        invalid.fields[pair.first] = parse(pair.second);
        rejects(invalid);
    }

    std::cout << "Client policy validation and grant tests passed\n";
}
