#include "../windows/update_verify.hpp"
#include <cassert>
#include <fstream>
#include <iostream>
#include <iterator>

template<class F> void rejects(F action) {
    bool failed = false;
    try { action(); } catch (const std::exception&) { failed = true; }
    assert(failed);
}
int main() {
    std::ifstream file("tests/fixtures/update-manifest-v1.json");
    assert(file.good());
    auto fixture = ohno_json::parse(std::string(std::istreambuf_iterator<char>(file), {}));
    const auto& fields = fixture.at("manifest");
    std::string document = "{";
    for (const auto& field : fields.fields) {
        if (document.size() > 1) document += ',';
        document += "\"" + field.first + "\":";
        document += field.second.type == ohno_json::value::kind::string ? "\"" + field.second.text + "\"" : field.second.text;
    }
    document += '}';
    auto key = fixture.at("public_key").text;
    auto verify = [&](const std::string& offer, const std::string& pinned) {
        return ohno::verify_update_offer(offer, pinned, 11, 1, 1793610000);
    };
    auto manifest = verify(document, key);
    assert(manifest.sequence == 12 && manifest.version == "0.2.0-alpha.1");
    for (const auto& old_value : {std::string("0.2.0-alpha.1"), std::string("4096"), std::string(64, 'a'), fields.at("signature").text}) {
        auto changed = document;
        auto at = changed.find(old_value);
        assert(at != std::string::npos);
        changed[at + old_value.size() - 1] = changed[at + old_value.size() - 1] == '0' ? '1' : '0';
        rejects([&] { verify(changed, key); });
    }
    rejects([&] { verify(document, "04" + std::string(128, '0')); });
    rejects([&] { verify(document, ""); });
    auto wrong_key = key;
    wrong_key.back() = wrong_key.back() == '0' ? '1' : '0';
    rejects([&] { verify(document, wrong_key); });
    rejects([&] { ohno::verify_update_offer(document, key, 12, 1, 1793610000); });
    rejects([&] { ohno::verify_update_offer(document, key, 11, 1, 1793613600); });
    std::cout << "Windows CNG verifies Python P-256 signature and rejects tampering/replay\n";
}
