#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
namespace ohno {
// Accepts the RawSMBIOSData returned by GetSystemFirmwareTable('RSMB', 0).
// Returns an opaque, locally used system UUID, or empty when absent/invalid.
inline std::string smbios_uuid(const std::vector<std::uint8_t>& data){
    if(data.size()<8)return {};
    const std::uint32_t length=static_cast<std::uint32_t>(data[4])|(static_cast<std::uint32_t>(data[5])<<8)|(static_cast<std::uint32_t>(data[6])<<16)|(static_cast<std::uint32_t>(data[7])<<24);
    if(length>data.size()-8)return {};
    const std::size_t end=8+length;std::size_t pos=8;
    while(pos+4<=end){
        auto type=data[pos], len=data[pos+1];if(len<4||pos+len>end)return {};
        if(type==1&&len>=24){
            bool all_zero=true,all_ff=true;for(unsigned i=0;i<16;i++){auto x=data[pos+8+i];all_zero=all_zero&&x==0;all_ff=all_ff&&x==255;}
            if(all_zero||all_ff)return {};
            const char* hex="0123456789abcdef";std::string out;out.reserve(32);
            for(unsigned i=0;i<16;i++){auto x=data[pos+8+i];out+=hex[x>>4];out+=hex[x&15];}return out;
        }
        std::size_t next=pos+len;
        while(next+1<end&&(data[next]!=0||data[next+1]!=0))++next;
        if(next+1>=end)return {};
        pos=next+2;
        if(type==127)break;
    }
    return {};
}
}
