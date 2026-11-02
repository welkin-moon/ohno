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
    std::cout << "Client policy validation and grant tests passed\n";
}
