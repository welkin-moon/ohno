#pragma once
#include "update_manifest.hpp"
#include <array>
#include <cstring>
#include <string_view>

namespace ohno {
constexpr std::array<const char*,6> update_payload_names{{"ohno-worker.exe","ohno-request.exe","ohno-maintenance.exe",
    "ohno-tun.exe","sing-box-LICENSE.txt","wintun-LICENSE.txt"}};
struct UpdateFileRange {std::size_t offset=0,size=0;};
struct UpdatePackage {std::string version;std::array<UpdateFileRange,6> files;};
namespace package_detail {
inline std::uint64_t le(std::string_view bytes,std::size_t offset,unsigned count){
    if(offset>bytes.size()||count>bytes.size()-offset)throw std::runtime_error("truncated update package integer");
    std::uint64_t value=0;for(unsigned i=0;i<count;++i)value|=std::uint64_t(static_cast<unsigned char>(bytes[offset+i]))<<(i*8);
    return value;
}
inline bool x64(std::string_view file){
    if(file.size()<1024||file.substr(0,2)!="MZ")return false;
    const auto offset=le(file,0x3c,4);
    return offset>=0x40&&offset<=file.size()-26&&file.substr(static_cast<std::size_t>(offset),4)==std::string_view("PE\0\0",4)&&
        le(file,static_cast<std::size_t>(offset)+4,2)==0x8664&&le(file,static_cast<std::size_t>(offset)+20,2)>=2&&
        le(file,static_cast<std::size_t>(offset)+24,2)==0x20b;
}
}
// This validates shape/architecture only. Verify the signed outer manifest,
// exact full package size/SHA256 and expected version BEFORE extraction/use.
inline UpdatePackage parse_update_package(std::string_view data){
    constexpr std::size_t header=60;
    if(data.size()<1024||data.size()>max_update_package_size||data.substr(0,8)!="OHNOPK01"||
        package_detail::le(data,10,2)!=6)throw std::runtime_error("invalid update package header");
    const auto length=package_detail::le(data,8,2);
    if(length<5||length>53)throw std::runtime_error("invalid update package version length");
    UpdatePackage package;package.version=std::string(data.substr(header,static_cast<std::size_t>(length)));
    if(!update_detail::version(package.version))throw std::runtime_error("invalid update package version");
    std::size_t pos=header+static_cast<std::size_t>(length);
    for(std::size_t index=0;index<package.files.size();++index){
        const auto size=package_detail::le(data,12+index*8,8);
        if(!size||size>max_update_package_size||pos>data.size()||size>data.size()-pos||
            (index>=4&&size>1024*1024))throw std::runtime_error("invalid update package file size");
        const auto count=static_cast<std::size_t>(size);
        if(index<4&&!package_detail::x64(data.substr(pos,count)))throw std::runtime_error("payload is not x64 PE32+");
        package.files[index]={pos,count};pos+=count;
    }
    if(pos!=data.size())throw std::runtime_error("trailing update package data");
    return package;
}
}
