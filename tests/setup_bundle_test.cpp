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
    auto corrupt=exe;corrupt[corrupt.size()-16]='\xff';
    assert(ohno::decode_school_bundle(corrupt,cfg)==ohno::BootstrapResult::Invalid);
    auto invalid_cert=exe;
    invalid_cert.replace(2+7000+server.size(),5,"hello");
    assert(ohno::decode_school_bundle(invalid_cert,cfg)==ohno::BootstrapResult::Invalid);
    auto nul_cert=exe;nul_cert[2+7000+server.size()+30]='\0';
    assert(ohno::decode_school_bundle(nul_cert,cfg)==ohno::BootstrapResult::Invalid);
    const std::string key="04"+std::string(128,'a');
    std::string trusted="MZ"+std::string(7000,'A')+server+cert+key;
    put32(trusted,static_cast<std::uint32_t>(server.size()));put32(trusted,static_cast<std::uint32_t>(cert.size()));put32(trusted,130);trusted+="OHNOBT02";
    assert(ohno::decode_school_bundle(trusted,cfg)==ohno::BootstrapResult::Ready&&cfg.release_public_key==key);
    auto invalid_key=trusted;invalid_key[invalid_key.size()-20-130]='3';
    assert(ohno::decode_school_bundle(invalid_key,cfg)==ohno::BootstrapResult::Invalid);
    invalid_key=trusted;invalid_key[invalid_key.size()-12]=0;
    assert(ohno::decode_school_bundle(invalid_key,cfg)==ohno::BootstrapResult::Invalid);
    assert(ohno::decode_school_bundle(exe,cfg)==ohno::BootstrapResult::Ready&&cfg.release_public_key.empty());
    return 0;
}
