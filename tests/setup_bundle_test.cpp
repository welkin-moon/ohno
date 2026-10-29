#include "../windows/setup_bundle.hpp"
#include <cassert>
#include <string>
#include <cstdint>

int main() {
    ohno::SchoolBootstrap cfg{};
    assert(ohno::decode_school_bundle("MZ-native-setup",cfg)==ohno::BootstrapResult::Missing);
    const std::string server="https://school-teacher:8443";
    const std::string cert="-----BEGIN CERTIFICATE-----\n"+std::string(150,'A')+"\n-----END CERTIFICATE-----\n";
    std::string exe="MZ"+std::string(7000,'A')+server+cert;
    auto put32=[](std::string& out,std::uint32_t n){
        for(unsigned i=0;i<4;i++)out+=static_cast<char>((n>>(8*i))&255);
    };
    put32(exe,static_cast<std::uint32_t>(server.size()));
    put32(exe,static_cast<std::uint32_t>(cert.size()));
    exe+="OHNOBT01";
    assert(ohno::decode_school_bundle(exe,cfg)==ohno::BootstrapResult::Ready);
    assert(cfg.server==L"https://school-teacher:8443");
    assert(cfg.certificate_pem==cert);
    // Installer reads only the last 17 KB of the EXE, not its entire body.
    assert(ohno::decode_school_bundle(exe.substr(1),cfg)==ohno::BootstrapResult::Ready);
    auto corrupt=exe;corrupt[corrupt.size()-16]=char(255);
    assert(ohno::decode_school_bundle(corrupt,cfg)==ohno::BootstrapResult::Invalid);
    auto invalid_cert=exe;
    invalid_cert.replace(2+7000+server.size(),5,"hello");
    assert(ohno::decode_school_bundle(invalid_cert,cfg)==ohno::BootstrapResult::Invalid);
    return 0;
}
