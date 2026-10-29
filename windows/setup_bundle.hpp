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
};
inline std::uint32_t le32(const unsigned char* p) {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1])<<8) |
           (std::uint32_t(p[2])<<16) | (std::uint32_t(p[3])<<24);
}
// Parse the end of an EXE produced by teacher/school_installer.py. A generic
// installer has no trailer and invokes the normal graphical setup screen.
inline BootstrapResult decode_school_bundle(const std::string& tail, SchoolBootstrap& config) {
    constexpr std::size_t trailer = 16;
    if (tail.size() < trailer) return BootstrapResult::Missing;
    const auto* end = reinterpret_cast<const unsigned char*>(tail.data()+tail.size()-trailer);
    if (std::memcmp(end+8,"OHNOBT01",8)!=0) return BootstrapResult::Missing;
    auto u=le32(end), c=le32(end+4);
    if (u==0 || u>1024 || c<100 || c>16384 || std::size_t(u)+c+trailer>tail.size())
        return BootstrapResult::Invalid;
    const std::size_t start=tail.size()-trailer-u-c;
    std::string url=tail.substr(start,u), cert=tail.substr(start+u,c);
    if (url.rfind("https://",0)!=0 || url.find_first_of("\r\n\t\0",0)!=std::string::npos ||
        cert.rfind("-----BEGIN CERTIFICATE-----",0)!=0 ||
        cert.find("-----END CERTIFICATE-----")==std::string::npos ||
        cert.find("PRIVATE KEY")!=std::string::npos)
        return BootstrapResult::Invalid;
    for (unsigned char ch:url) if(ch<33 || ch>126) return BootstrapResult::Invalid;
    config.server.assign(url.begin(),url.end());
    config.certificate_pem=std::move(cert);
    return BootstrapResult::Ready;
}
#ifdef _WIN32
BootstrapResult read_school_bundle(SchoolBootstrap& config);
#endif
}
