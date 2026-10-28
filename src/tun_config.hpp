#pragma once
#include "policy.hpp"
#include <stdexcept>
#include <string>
#include <vector>
namespace ohno {
// Input hostnames are validated ASCII; file:// rules stay in the browser policy.
inline std::string tun_config(const std::vector<std::string>& blocked,const std::vector<std::string>& allow){
    auto array=[](const std::vector<std::string>& hosts,bool allow_dot){
        std::string out="[";bool first=true;
        for(auto h:hosts){
            if(h=="file://*")continue;
            if(allow_dot&&h.size()>1&&h[0]=='.')h.erase(0,1);
            if(!valid_hostname(h))throw std::runtime_error("invalid TUN hostname");
            if(!first)out+=",";
            first=false;out+="\""+h+"\"";
        }
        return out+"]";
    };
    const auto deny=array(blocked,false),permit=array(allow,true);
    std::string rules="{\"action\":\"sniff\",\"timeout\":\"300ms\"}";
    if(permit!="[]")rules+=",{\"domain\":"+permit+",\"action\":\"route\",\"outbound\":\"direct\"}";
    if(deny!="[]")rules+=",{\"domain_suffix\":"+deny+",\"action\":\"reject\"}";
    return "{\"log\":{\"level\":\"warn\"},\"inbounds\":[{\"type\":\"tun\",\"tag\":\"tun-in\",\"interface_name\":\"ohno-tun\",\"address\":[\"198.18.0.1/30\",\"fdfe:dcba:9876::1/126\"],\"mtu\":1500,\"auto_route\":true,\"strict_route\":false,\"dns_mode\":\"disabled\",\"stack\":\"system\",\"route_exclude_address\":[\"10.0.0.0/8\",\"172.16.0.0/12\",\"192.168.0.0/16\",\"169.254.0.0/16\",\"fc00::/7\"]}],\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"route\":{\"auto_detect_interface\":true,\"rules\":["+rules+"],\"final\":\"direct\"}}";
}
}
