#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ohno {
// Identifiers for inventory and clone detection, never a replacement for a secret key.
struct NicIdentityCandidate {
    std::array<std::uint8_t, 6> address{};
    bool wired = false;
    bool hardware = false; // driver reports a physical NIC with a permanent MAC
};
inline bool valid_mac_bytes(const std::array<std::uint8_t, 6>& mac) {
    if (mac[0] & 1) return false; // multicast/broadcast
    return std::any_of(mac.begin(), mac.end(), [](std::uint8_t b) { return b != 0; });
}
inline std::string format_mac(const std::array<std::uint8_t, 6>& mac) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(17);
    for (std::size_t i = 0; i < mac.size(); ++i) {
        if (i) result += ':';
        result += hex[mac[i] >> 4];
        result += hex[mac[i] & 15];
    }
    return result;
}
// Prefer permanent hardware Ethernet, then Wi-Fi. Sort independently of IP
// and link state so DHCP renewals / unplugged cables do not change identity.
// Virtual/observed addresses are only used when no hardware NIC is exposed.
inline std::vector<std::string> stable_macs(const std::vector<NicIdentityCandidate>& candidates) {
    bool hardware_found = std::any_of(candidates.begin(), candidates.end(),
        [](const NicIdentityCandidate& c) { return c.hardware && valid_mac_bytes(c.address); });
    std::vector<std::pair<int, std::string>> ordered;
    for (const auto& c : candidates) {
        if (!valid_mac_bytes(c.address) || (hardware_found && !c.hardware)) continue;
        ordered.emplace_back(c.wired ? 0 : 1, format_mac(c.address));
    }
    std::sort(ordered.begin(), ordered.end());
    std::vector<std::string> macs;
    for (const auto& entry : ordered) {
        if (std::find(macs.begin(), macs.end(), entry.second) == macs.end())
            macs.push_back(entry.second);
        if (macs.size() == 16) break;
    }
    return macs;
}
inline std::string hardware_anchor(const std::string& smbios_uuid, const std::vector<std::string>& macs) {
    if (macs.empty()) return smbios_uuid;
    return smbios_uuid.empty() ? "mac:" + macs.front() : smbios_uuid + "|mac:" + macs.front();
}
}
