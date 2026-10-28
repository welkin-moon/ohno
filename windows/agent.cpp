#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 // Target the Windows 10 IP Helper interfaces.
#endif
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <sddl.h>
#include <string>
#include <vector>
#include <stdexcept>
#include "agent.hpp"
#include "monitor.hpp"
#include "browser_policy.hpp"
#include "network_filter.hpp"
#include "request_pipe.hpp"
#include "tun_manager.hpp"
#include <algorithm>
#include <array>
#include <cwctype>
#include <cstdint>
#include <ctime>
#include <map>
#include <set>
#include <mutex>
#include "../src/json.hpp"
#include "../src/smbios.hpp"
#include "../src/mac_identity.hpp"
#include "../src/policy.hpp"
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
namespace {
struct reg_key { HKEY h=nullptr; ~reg_key(){if(h)RegCloseKey(h);} };
struct http_handle { HINTERNET h=nullptr; ~http_handle(){if(h)WinHttpCloseHandle(h);} };
void debug(const wchar_t* s){OutputDebugStringW(s);}
std::string utf8(const std::wstring& s) {
    if(s.empty()) return {};
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
    if(n<=0)throw std::runtime_error("utf8 conversion");
    std::string r(static_cast<std::size_t>(n),'\0');
    if(!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),r.data(),n,nullptr,nullptr))throw std::runtime_error("utf8 conversion");
    return r;
}
std::wstring wide_ascii(const std::string& s){std::wstring out;for(unsigned char c:s){if(c>127)throw std::runtime_error("invalid ascii");out.push_back(static_cast<wchar_t>(c));}return out;}
std::string quoted(const std::string& s){
    static const char* hex="0123456789abcdef";std::string out="\"";
    for(unsigned char c:s){if(c=='"'||c=='\\'){out+='\\';out+=static_cast<char>(c);}else if(c<32){out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}else out+=static_cast<char>(c);}return out+'"';
}
std::wstring read_string(HKEY key,const wchar_t* name){
    DWORD type=0,size=0;if(RegQueryValueExW(key,name,nullptr,&type,nullptr,&size)!=ERROR_SUCCESS||type!=REG_SZ||size<sizeof(wchar_t)||size>8192||size%sizeof(wchar_t))return {};
    std::vector<wchar_t> data(size/sizeof(wchar_t)+1,0);
    if(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE*>(data.data()),&size)!=ERROR_SUCCESS||type!=REG_SZ)return {};
    return std::wstring(data.data());
}
void write_string(HKEY key,const wchar_t* name,const std::wstring& s){
    if(RegSetValueExW(key,name,0,REG_SZ,reinterpret_cast<const BYTE*>(s.c_str()),static_cast<DWORD>((s.size()+1)*sizeof(wchar_t)))!=ERROR_SUCCESS)throw std::runtime_error("registry write");
}
std::string random_hex(std::size_t count){
    std::vector<unsigned char> bytes(count);if(BCryptGenRandom(nullptr,bytes.data(),static_cast<ULONG>(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw std::runtime_error("random failed");
    const char* hex="0123456789abcdef";std::string result;result.reserve(count*2);for(auto b:bytes){result+=hex[b>>4];result+=hex[b&15];}return result;
}
struct identity{std::string id,key;std::vector<std::string> macs;};
struct secret_text{std::string value;~secret_text(){if(!value.empty())SecureZeroMemory(value.data(),value.size());}};
std::mutex identity_mutex;
// Read NIC identities directly from the OS; DHCP IPs and route metrics are ignored.
std::vector<std::string> network_macs(){
    constexpr ULONG flags=GAA_FLAG_INCLUDE_ALL_INTERFACES|GAA_FLAG_SKIP_UNICAST|
        GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER;
    ULONG bytes=15*1024,status=ERROR_BUFFER_OVERFLOW;
    std::vector<unsigned char> buffer;
    for(int attempt=0;attempt<3;++attempt){
        buffer.resize(bytes);
        status=GetAdaptersAddresses(AF_UNSPEC,flags,nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),&bytes);
        if(status!=ERROR_BUFFER_OVERFLOW||bytes>1024*1024)break;
    }
    if(status!=NO_ERROR)return {};
    std::vector<ohno::NicIdentityCandidate> candidates;
    for(auto* adapter=reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());adapter;adapter=adapter->Next){
        if(adapter->IfType!=IF_TYPE_ETHERNET_CSMACD&&adapter->IfType!=IF_TYPE_IEEE80211)continue;
        if(adapter->FriendlyName){
            std::wstring friendly(adapter->FriendlyName);
            std::transform(friendly.begin(),friendly.end(),friendly.begin(),
                [](wchar_t ch){return static_cast<wchar_t>(std::towlower(ch));});
            if(friendly.find(L"ohno")!=std::wstring::npos||friendly.find(L"wintun")!=std::wstring::npos)continue;
        }
        MIB_IF_ROW2 row{};
        row.InterfaceLuid=adapter->Luid;
        bool hardware=GetIfEntry2(&row)==NO_ERROR &&
            row.InterfaceAndOperStatusFlags.HardwareInterface &&
            !row.InterfaceAndOperStatusFlags.FilterInterface &&
            !row.InterfaceAndOperStatusFlags.EndPointInterface &&
            row.PhysicalAddressLength==6;
        std::array<std::uint8_t,6> mac{};
        if(hardware)std::copy_n(row.PermanentPhysicalAddress,6,mac.begin());
        if(!hardware||!ohno::valid_mac_bytes(mac)){
            if(adapter->PhysicalAddressLength!=6)continue;
            std::copy_n(adapter->PhysicalAddress,6,mac.begin());
            hardware=false;
        }
        candidates.push_back({mac,adapter->IfType==IF_TYPE_ETHERNET_CSMACD,hardware});
    }
    return ohno::stable_macs(candidates);
}
std::string machine_anchor(const std::vector<std::string>& macs){
    constexpr DWORD rsmb=0x52534d42; // 'RSMB'
    std::string uuid;
    UINT size=GetSystemFirmwareTable(rsmb,0,nullptr,0);
    if(size>=8&&size<=4*1024*1024){
        std::vector<std::uint8_t> data(size);
        if(GetSystemFirmwareTable(rsmb,0,data.data(),size)==size)uuid=ohno::smbios_uuid(data);
    }
    const auto anchor=ohno::hardware_anchor(uuid,macs);
    if(anchor.empty())throw std::runtime_error("No SMBIOS UUID or identifiable network adapter");
    return anchor;
}
identity get_identity(){
    std::lock_guard<std::mutex> lock(identity_mutex);
    const auto macs=network_macs();
    if(macs.empty())throw std::runtime_error("No usable network adapter MAC");
    const auto anchor=machine_anchor(macs);
    PSECURITY_DESCRIPTOR sd=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;KA;;;SY)(A;;KA;;;BA)",SDDL_REVISION_1,&sd,nullptr))throw std::runtime_error("security descriptor");
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};reg_key key;
    LONG status=RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno\\Identity",0,nullptr,0,KEY_READ|KEY_WRITE,&sa,&key.h,nullptr);
    LocalFree(sd);if(status!=ERROR_SUCCESS)throw std::runtime_error("identity key");
    const std::string stored=utf8(read_string(key.h,L"Credentials"));
    if(stored.size()==anchor.size()+98&&stored.compare(0,anchor.size(),anchor)==0&&
        stored[anchor.size()]==':'&&stored[anchor.size()+33]==':')
        return {stored.substr(anchor.size()+1,32),stored.substr(anchor.size()+34,64),macs};
    if(!clear_edge_policy()||!clear_edge_allow_policy())throw std::runtime_error("cannot clear copied browser policy");
    RegDeleteValueW(key.h,L"Policy"); // copied policies and grants must not follow cloned credentials
    auto newid=random_hex(16),newkey=random_hex(32);
    // A single registry value avoids persisting a partial id/key/anchor update.
    write_string(key.h,L"Credentials",wide_ascii(anchor+":"+newid+":"+newkey));
    return {newid,newkey,macs};
}
std::string cached_policy(){
    reg_key key;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno\\Identity",0,KEY_READ,&key.h)!=ERROR_SUCCESS)return {};
    DWORD type=0,size=0;if(RegQueryValueExW(key.h,L"Policy",nullptr,&type,nullptr,&size)!=ERROR_SUCCESS||type!=REG_BINARY||size>1024*1024)return {};
    std::string s(size,'\0');if(RegQueryValueExW(key.h,L"Policy",nullptr,&type,reinterpret_cast<BYTE*>(s.data()),&size)!=ERROR_SUCCESS||type!=REG_BINARY)return {};s.resize(size);return s;
}
void save_policy(const std::string& value){
    reg_key key;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno\\Identity",0,KEY_WRITE,&key.h)!=ERROR_SUCCESS)throw std::runtime_error("policy key");
    if(RegSetValueExW(key.h,L"Policy",0,REG_BINARY,reinterpret_cast<const BYTE*>(value.data()),static_cast<DWORD>(value.size()))!=ERROR_SUCCESS)throw std::runtime_error("policy save");
}
void validate_policy(const ohno_json::value& p){
    if(p.at("program_hashes").type!=ohno_json::value::kind::array||p.at("grants").type!=ohno_json::value::kind::array||p.at("web_domains").type!=ohno_json::value::kind::array||p.at("program_names").type!=ohno_json::value::kind::array||p.at("block_local_files").type!=ohno_json::value::kind::boolean)throw std::runtime_error("invalid policy");
}
std::wstring get_server(){
    reg_key key;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&key.h)!=ERROR_SUCCESS)return {};
    return read_string(key.h,L"ServerUrl");
}
struct response{DWORD status=0;std::string body;};
response request(const std::wstring& url,const wchar_t* method,const wchar_t* path,const std::wstring& headers,const std::string& body){
    URL_COMPONENTS parts{};parts.dwStructSize=sizeof(parts);parts.dwHostNameLength=static_cast<DWORD>(-1);parts.dwSchemeLength=static_cast<DWORD>(-1);parts.dwUrlPathLength=static_cast<DWORD>(-1);parts.dwExtraInfoLength=static_cast<DWORD>(-1);parts.dwUserNameLength=static_cast<DWORD>(-1);parts.dwPasswordLength=static_cast<DWORD>(-1);
    if(!WinHttpCrackUrl(url.c_str(),static_cast<DWORD>(url.size()),0,&parts)||parts.nScheme!=INTERNET_SCHEME_HTTPS||parts.dwHostNameLength==0||parts.dwUserNameLength||parts.dwPasswordLength||parts.dwExtraInfoLength||parts.dwUrlPathLength>1)throw std::runtime_error("invalid HTTPS URL");
    std::wstring host(parts.lpszHostName,parts.dwHostNameLength);
    http_handle session{WinHttpOpen(L"ohno/0.1",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0)};
    if(!session.h)throw std::runtime_error("winhttp open");
    WinHttpSetTimeouts(session.h,5000,5000,5000,5000);
    http_handle conn{WinHttpConnect(session.h,host.c_str(),parts.nPort,0)};
    if(!conn.h)throw std::runtime_error("winhttp connect");
    http_handle req{WinHttpOpenRequest(conn.h,method,path,nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE)};
    if(!req.h)throw std::runtime_error("winhttp request");
    if(!WinHttpSendRequest(req.h,headers.empty()?WINHTTP_NO_ADDITIONAL_HEADERS:headers.c_str(),headers.empty()?0:static_cast<DWORD>(-1L),body.empty()?WINHTTP_NO_REQUEST_DATA:const_cast<char*>(body.data()),static_cast<DWORD>(body.size()),static_cast<DWORD>(body.size()),0)||!WinHttpReceiveResponse(req.h,nullptr))throw std::runtime_error("HTTPS request failed");
    response out;DWORD bytes=sizeof(out.status);
    if(!WinHttpQueryHeaders(req.h,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&out.status,&bytes,WINHTTP_NO_HEADER_INDEX))throw std::runtime_error("HTTP status failed");
    for(;;){DWORD available=0;if(!WinHttpQueryDataAvailable(req.h,&available))throw std::runtime_error("HTTP read failed");if(!available)break;if(out.body.size()+available>1024*1024)throw std::runtime_error("response too large");std::vector<char> buf(available);DWORD n=0;if(!WinHttpReadData(req.h,buf.data(),available,&n)||n==0)throw std::runtime_error("HTTP read failed");out.body.append(buf.data(),n);}
    return out;
}
}
void run_agent(HANDLE stop_event){
    auto on_request=[](const std::string& payload)->std::string{
        try{
            auto server=get_server();if(server.empty())return "unavailable";auto ident=get_identity();
            auto headers=L"X-Ohno-Device: "+wide_ascii(ident.id)+L"\r\nX-Ohno-Key: "+wide_ascii(ident.key)+L"\r\nContent-Type: application/json\r\n";
            bool unlock=payload.rfind("U:",0)==0;
            secret_text body;body.value=unlock?"{\"password\":"+quoted(payload.substr(2))+"}":"{\"kind\":\"website\",\"object\":"+quoted(payload.substr(2))+"}";
            auto r=request(server,L"POST",unlock?L"/api/device/unlock":L"/api/device/request",headers,body.value);
            return r.status==201?"accepted":r.status==403?"denied":"unavailable";
        }catch(const std::exception&){return "unavailable";}
    };
    RequestPipe website_requests(stop_event,on_request);
    TunManager tun(stop_event);
    std::vector<std::string> tun_blocked,tun_allowed;
    try{
        get_identity();auto cached=cached_policy();
        if(!cached.empty()){auto p=ohno_json::parse(cached);validate_policy(p);for(const auto& d:p.at("web_domains").items)if(d.type==ohno_json::value::kind::string)tun_blocked.push_back(d.text);}
    }catch(const std::exception&){debug(L"ohno: cached TUN policy unavailable\n");}
    NetworkFilter network;
    if(!network.available())debug(L"ohno: WFP unavailable; outbound protection disabled\n");
    std::map<std::string,ULONGLONG> last_request;
    std::map<std::string,std::wstring> queued;
    while(WaitForSingleObject(stop_event,0)==WAIT_TIMEOUT){
        bool tun_ok=tun.ensure(tun_blocked,tun_allowed);
        try{
            auto server=get_server();if(server.empty())throw std::runtime_error("server URL not configured");
            auto ident=get_identity();auto policy_text=cached_policy();bool online=false;
            auto h=L"X-Ohno-Device: "+wide_ascii(ident.id)+L"\r\nX-Ohno-Key: "+wide_ascii(ident.key)+L"\r\n";
            try{
                wchar_t name[MAX_COMPUTERNAME_LENGTH+1]{};DWORD n=MAX_COMPUTERNAME_LENGTH+1;
                std::wstring pc=GetComputerNameW(name,&n)?std::wstring(name,n):L"unknown";
                std::string mac_json="[";
                for(const auto& mac:ident.macs){if(mac_json.size()>1)mac_json+=",";mac_json+=quoted(mac);}
                mac_json+="]";
                std::string data="{\"id\":"+quoted(ident.id)+",\"key\":"+quoted(ident.key)+",\"name\":"+quoted(utf8(pc))+
                    ",\"macs\":"+mac_json+",\"primary_mac\":"+quoted(ident.macs.empty()?"":ident.macs.front())+
                    ",\"tun\":"+(tun_ok?"true":"false")+",\"wfp\":"+(network.available()?"true":"false")+"}";
                auto reg=request(server,L"POST",L"/api/device/register",L"Content-Type: application/json\r\n",data);
                if(reg.status==200||reg.status==201){
                    auto result=ohno_json::parse(reg.body);const auto& approved=result.at("approved");
                    if(approved.type!=ohno_json::value::kind::boolean)throw std::runtime_error("invalid registration response");
                    if(!approved.boolean)debug(L"ohno: device pending approval\n");
                    else{
                        auto policy=request(server,L"GET",L"/api/device/policy",h,{});
                        if(policy.status==200){auto candidate=ohno_json::parse(policy.body);validate_policy(candidate);save_policy(policy.body);policy_text=policy.body;online=true;}
                        else if(policy.status==403)debug(L"ohno: device approval revoked\n");
                    }
                }
            }catch(const std::exception&){debug(L"ohno: offline; applying cached policy\n");}
            if(!policy_text.empty()){
                auto p=ohno_json::parse(policy_text);validate_policy(p);
                const auto& rules=p.at("program_hashes");const auto& grants=p.at("grants");const auto& web=p.at("web_domains");const auto& name_rules=p.at("program_names");
                std::vector<std::string> domains;for(const auto& item:web.items)if(item.type==ohno_json::value::kind::string)domains.push_back(item.text);
                if(p.at("block_local_files").boolean)domains.push_back("file://*");
                std::vector<std::string> names;for(const auto& item:name_rules.items)if(item.type==ohno_json::value::kind::string)names.push_back(item.text);
                std::vector<std::string> allowed,network_allowed,site_allowed;bool paused=false;
                std::vector<std::string> blocked;for(const auto& item:rules.items)if(item.type==ohno_json::value::kind::string&&item.text.size()==64)blocked.push_back(item.text);
                if(online)for(const auto& grant:grants.items){
                    const auto& kind=grant.at("kind");const auto& object=grant.at("object");const auto& expiry=grant.at("expires");
                    if(kind.type==ohno_json::value::kind::string&&object.type==ohno_json::value::kind::string&&expiry.type==ohno_json::value::kind::number){
                        try{if(std::stoll(expiry.text)>static_cast<long long>(std::time(nullptr))){if(kind.text=="application")allowed.push_back(object.text);else if(kind.text=="network")network_allowed.push_back(object.text);else if(kind.text=="website"&&ohno::valid_hostname(object.text))site_allowed.push_back("."+object.text);else if(kind.text=="pause"&&object.text=="*")paused=true;}}catch(const std::exception&){}
                    }
                }
                if(paused)domains.clear();
                tun_blocked=domains;tun_allowed=site_allowed;
                if(!tun.ensure(tun_blocked,tun_allowed))debug(L"ohno: TUN unavailable or restarting\n");
                if(!apply_edge_policy(domains))debug(L"ohno: Edge policy update failed\n");
                if(!apply_edge_allow_policy(site_allowed))debug(L"ohno: Edge allow policy update failed\n");
                network.set_paused(paused);
                if(!paused)for(const auto& app:stop_matching_processes(blocked,names,allowed,0,stop_event)){
                    auto now=GetTickCount64();auto it=last_request.find(app.hash);
                    if(it==last_request.end()||now-it->second>=60000){last_request[app.hash]=now;queued.emplace("A:"+app.hash,app.name);}
                }
                network.apply_grants(network_allowed);
                if(!paused)for(const auto& app:observe_untrusted_programs(stop_event)){
                    if(std::find(network_allowed.begin(),network_allowed.end(),app.hash)!=network_allowed.end())continue;
                    if(network.register_untrusted(app.path,app.hash)){
                        auto name="N:"+app.hash;auto now=GetTickCount64();auto it=last_request.find(name);
                        if(it==last_request.end()||now-it->second>=60000){last_request[name]=now;auto split=app.path.find_last_of(L"\\/");queued.emplace(name,split==std::wstring::npos?app.path:app.path.substr(split+1));notify_network_block(app.pid);}
                    }
                }
            }
            if(online){
                for(auto it=queued.begin();it!=queued.end();){
                    try{auto prefix=it->first.substr(0,2);auto kind=prefix=="N:"?"network":"application";auto body="{\"kind\":"+quoted(kind)+",\"object\":"+quoted(it->first.substr(2))+",\"label\":"+quoted(utf8(it->second))+"}";
                        auto response=request(server,L"POST",L"/api/device/request",h+L"Content-Type: application/json\r\n",body);
                        if(response.status==201)it=queued.erase(it);else break;
                    }catch(const std::exception&){break;}
                }
            }
        }catch(const std::exception&){debug(L"ohno: service iteration failed\n");}
        if(WaitForSingleObject(stop_event,15000)!=WAIT_TIMEOUT)break;
    }
}
