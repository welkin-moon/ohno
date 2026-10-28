#include "../src/mac_identity.hpp"
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    using ohno::NicIdentityCandidate;
    NicIdentityCandidate wifi{{0x24,0x33,0x44,0x55,0x66,0x77},false,true};
    NicIdentityCandidate wired{{0x00,0x15,0x5d,0x11,0x22,0x33},true,true};
    NicIdentityCandidate tun{{0x02,0xaa,0xbb,0xcc,0xdd,0xee},true,false};
    auto macs = ohno::stable_macs({wifi,tun,wired,wifi});
    assert((macs == std::vector<std::string>{"00:15:5d:11:22:33","24:33:44:55:66:77"}));
    assert(ohno::hardware_anchor("uuid",macs) == "uuid|mac:00:15:5d:11:22:33");
    assert(ohno::hardware_anchor("uuid",ohno::stable_macs({wifi,wired})) == ohno::hardware_anchor("uuid",macs));
    assert(ohno::hardware_anchor("uuid",{"00:15:5d:11:22:34"}) != ohno::hardware_anchor("uuid",macs));
    assert(ohno::hardware_anchor("",macs) == "mac:00:15:5d:11:22:33");
    assert(ohno::hardware_anchor("uuid",{}) == "uuid");
    auto fallback = ohno::stable_macs({tun});
    assert(fallback.size() == 1 && fallback.front() == "02:aa:bb:cc:dd:ee");
    NicIdentityCandidate multicast{{0x01,0x00,0x5e,0,0,1},true,true};
    NicIdentityCandidate empty{{0,0,0,0,0,0},true,true};
    assert(ohno::stable_macs({multicast,empty}).empty());
}
