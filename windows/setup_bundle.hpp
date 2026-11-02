#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace ohno {
enum class BootstrapResult { Missing, Invalid, Ready };
struct SchoolBootstrap {
    std::wstring server;
    std::string certificate_pem;
    std::string release_public_key;
};
inline std::uint32_t le32(const unsigned char* p) {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1])<<8) |
           (std::uint32_t(p[2])<<16) | (std::uint32_t(p[3])<<24);
}
// Parse the end of an EXE produced by teacher/school_installer.py. A generic
// installer has no trailer and invokes the normal graphical setup screen.
inline BootstrapResult decode_school_bundle(const std::string& tail, SchoolBootstrap& config) {
    if(tail.size()<16)return BootstrapResult::Missing;
    const bool v2=tail.compare(tail.size()-8,8,"OHNOBT02")==0;
    const std::size_t trailer=v2?20:16;
    if(tail.size()<trailer)return BootstrapResult::Invalid;
    const auto* end=reinterpret_cast<const unsigned char*>(tail.data()+tail.size()-trailer);
    if(!v2&&std::memcmp(end+8,"OHNOBT01",8)!=0)return BootstrapResult::Missing;
    auto u=le32(end),c=le32(end+4),k=v2?le32(end+8):0;
    if(u==0||u>1024||c<100||c>16384||(v2&&k!=130)||std::size_t(u)+c+k+trailer>tail.size())return BootstrapResult::Invalid;
    const std::size_t start=tail.size()-trailer-u-c-k;
    std::string url=tail.substr(start,u),cert=tail.substr(start+u,c),key=tail.substr(start+u+c,k);
    if(v2){
        if(key.substr(0,2)!="04")return BootstrapResult::Invalid;
        for(char ch:key)if(!((ch>='0'&&ch<='9')||(ch>='a'&&ch<='f')))return BootstrapResult::Invalid;
    }
    if (url.rfind("https://",0)!=0 || url.find_first_of("\r\n\t\0",0)!=std::string::npos ||
        cert.rfind("-----BEGIN CERTIFICATE-----",0)!=0 ||
        cert.find("-----END CERTIFICATE-----")==std::string::npos ||
        cert.find('\0')!=std::string::npos ||
        cert.find("PRIVATE KEY")!=std::string::npos)
        return BootstrapResult::Invalid;
    for (unsigned char ch:url) if(ch<33 || ch>126) return BootstrapResult::Invalid;
    config.server.assign(url.begin(),url.end());
    config.certificate_pem=std::move(cert);
    config.release_public_key=std::move(key);
    return BootstrapResult::Ready;
}
#ifdef _WIN32
BootstrapResult read_school_bundle(SchoolBootstrap& config);
#endif
}
