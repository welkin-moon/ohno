#include "approval_queue.hpp"
#include "json.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <vector>

int main() {
    const std::string a(64, 'a'), b(64, 'b');
    ohno::ApprovalQueue queue;
    assert(!queue.enqueue("application", "", L"unhashable.exe"));
    assert(!queue.enqueue("website", a, L"wrong kind"));
    assert(queue.enqueue("application", a, L"bad request"));
    assert(queue.enqueue("application", b, L"valid request"));
    queue.enqueue("application", b, L"duplicate");
    assert(queue.size() == 2);
    std::vector<std::string> sent;
    queue.flush([&](const std::string&, const std::string& hash, const std::wstring&) {
        sent.push_back(hash);
        return hash == a ? 400u : 201u;
    });
    assert(sent == (std::vector<std::string>{a, b}));
    assert(queue.size() == 0); // A permanent error cannot block later requests.
    for (auto status : {401u, 403u, 408u, 429u, 500u, 503u}) {
        queue.enqueue("network", a, L"retry");
        queue.enqueue("network", b, L"later");
        unsigned calls = 0;
        queue.flush([&](const auto&, const auto&, const auto&) { ++calls; return status; });
        assert(calls == 1 && queue.size() == 2);
        queue.flush([](const auto&, const auto&, const auto&) -> unsigned {
            throw std::runtime_error("offline");
        });
        assert(queue.size() == 2);
        queue.flush([](const auto&, const auto&, const auto&) { return 201u; });
        assert(queue.size() == 0);
    }
    assert(ohno::approval_label(std::string(250, 'x')) == std::string(128, 'x'));
    const std::string emoji = "\xf0\x9f\x98\x80";
    std::string long_name;
    for (int i = 0; i < 140; ++i) long_name += emoji;
    auto label = ohno::approval_label(long_name);
    assert(label.size() == 128*emoji.size());
    assert(ohno_json::parse("\"" + label + "\"").text == label);
    assert(ohno::approval_label("a/b\\c\x7f\t.exe") == "a_b_c__.exe");
    std::cout << "Approval queue retry and label tests passed\n";
}
