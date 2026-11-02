#include "update_manifest.hpp"
#include <cassert>
#include <fstream>
#include <iostream>
#include <iterator>

std::string serialize(const ohno_json::value& value) {
    using kind = ohno_json::value::kind;
    if (value.type == kind::string) return "\"" + value.text + "\""; // Test inputs below contain no escapes.
    if (value.type == kind::number) return value.text;
    if (value.type == kind::boolean) return value.boolean ? "true" : "false";
    if (value.type == kind::null) return "null";
    std::string output = "{";
    for (const auto& field : value.fields) {
        if (output.size() > 1) output += ',';
        output += "\"" + field.first + "\":" + serialize(field.second);
    }
    return output + '}';
}
template<class F> void rejects(F action) {
    bool failed = false;
    try { action(); } catch (const std::exception&) { failed = true; }
    assert(failed);
}
int main() {
    std::ifstream file("tests/fixtures/update-manifest-v1.json");
    assert(file.good());
    auto fixture = ohno_json::parse(std::string(std::istreambuf_iterator<char>(file), {}));
    auto valid = fixture.at("manifest");
    auto document = serialize(valid);
    auto manifest = ohno::parse_update_manifest(document);
    assert(manifest.sequence == 12 && manifest.size == 4096);
    assert(ohno::update_signing_bytes(manifest) == fixture.at("signing_bytes").text);
    assert(ohno::update_package_path(manifest) == "/api/device/update/package/" + std::string(64, 'a'));
    for (auto now : {1793609700ULL, 1793610000ULL, 1793613599ULL}) ohno::require_new_update(manifest, 11, 1, now);
    for (auto now : std::vector<std::uint64_t>{0ULL, 1793609699ULL, 1793613600ULL, ohno::max_update_timestamp + 1})
        rejects([&] { ohno::require_new_update(manifest, 11, 1, now); });
    for (auto sequence : std::vector<std::uint64_t>{12ULL, 13ULL, ohno::max_update_sequence + 1})
        rejects([&] { ohno::require_new_update(manifest, sequence, 1, 1793610000); });
    for (auto updater : {0ULL, 65536ULL}) rejects([&] { ohno::require_new_update(manifest, 11, updater, 1793610000); });
    manifest.min_updater = 2;
    rejects([&] { ohno::require_new_update(manifest, 11, 1, 1793610000); });
    for (const auto& field : {"schema", "sequence", "min_updater", "issued_at", "expires_at", "size"}) {
        for (const auto& value : {"true", "false", "null", "\"1\"", "1.0", "1e0", "-1", "0", "18446744073709551617", "99999999999999999999999999999999999999"}) {
            auto bad = valid;
            bad.fields[field] = ohno_json::parse(value);
            rejects([&] { ohno::parse_update_manifest(serialize(bad)); });
        }
    }
    for (const auto& change : std::vector<std::pair<std::string, std::string>>{
            {"schema", "2"}, {"platform", "\"windows-arm64\""}, {"sequence", "9007199254740992"},
            {"min_updater", "65536"}, {"issued_at", "253402300800"}, {"expires_at", "1793610000"},
            {"expires_at", "1794214801"}, {"size", "1023"}, {"size", "268435457"},
            {"version", "\"01.2.3\""}, {"version", "\"1.2.3-\""}, {"version", "\"1.2.3/../\""},
            {"version", "\"1000000.0.0\""}, {"sha256", "\"short\""}, {"signature", "\"short\""}}) {
        auto bad = valid;
        bad.fields[change.first] = ohno_json::parse(change.second);
        rejects([&] { ohno::parse_update_manifest(serialize(bad)); });
    }
    for (const auto& field : valid.fields) {
        auto bad = valid;
        bad.fields.erase(field.first);
        rejects([&] { ohno::parse_update_manifest(serialize(bad)); });
    }
    auto bad = valid;
    bad.fields["url"] = ohno_json::parse("\"https://evil.example/update.exe\"");
    rejects([&] { ohno::parse_update_manifest(serialize(bad)); });
    rejects([&] { ohno::parse_update_manifest(document.substr(0, document.size()-1) + ",\"sequence\":12}"); });
    rejects([&] { ohno::parse_update_manifest(document + std::string(4096, ' ')); });
    std::cout << "Update manifest validation, transcript and anti-replay tests passed\n";
}
