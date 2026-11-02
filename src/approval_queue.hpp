#pragma once
#include "policy.hpp"
#include <cstdint>
#include <exception>
#include <map>
#include <string>
#include <utility>

namespace ohno {
// Input is valid UTF-8 from the Windows conversion routine. Keep labels within
// the teacher API's limit without splitting a multibyte character.
inline std::string approval_label(std::string text) {
    std::size_t characters = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        if ((c & 0xc0) != 0x80 && ++characters > 128) {
            text.resize(i);
            break;
        }
        if (c < 32 || c == 127 || c == '/' || c == '\\') text[i] = '_';
    }
    return text;
}

inline bool permanent_approval_error(std::uint32_t status) {
    return status >= 400 && status < 500 && status != 401 && status != 403 &&
           status != 408 && status != 429;
}

class ApprovalQueue {
    using Key = std::pair<std::string, std::string>;
    std::map<Key, std::wstring> items_;
public:
    bool enqueue(const std::string& kind, const std::string& hash, const std::wstring& label) {
        if ((kind != "application" && kind != "network") || !valid_sha256(hash)) return false;
        items_.emplace(Key{kind, hash}, label);
        return true;
    }
    std::size_t size() const { return items_.size(); }

    template<class Send>
    void flush(Send send) {
        for (auto it = items_.begin(); it != items_.end();) {
            try {
                auto status = send(it->first.first, it->first.second, it->second);
                if (status == 201 || permanent_approval_error(status)) it = items_.erase(it);
                else break; // Authentication, capacity and transport failures can recover.
            } catch (const std::exception&) {
                break;
            }
        }
    }
};
}
