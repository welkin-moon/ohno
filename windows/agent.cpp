#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <sddl.h>
#include <string>
#include <vector>
#include <stdexcept>
#include "agent.hpp"
#include "monitor.hpp"
#include "browser_policy.hpp"
#include <algorithm>
#include <ctime>
#include <map>
#include <set>
#include "../src/json.hpp"
#include "../src/smbios.hpp"
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
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
struct identity{std::string id,key;};
std::string machine_anchor(){
    constexpr DWORD rsmb=0x52534d42; // 'RSMB'
    UINT size=GetSystemFirmwareTable(rsmb,0,nullptr,0);
    if(size<8||size>4*1024*1024)throw std::runtime_error("SMBIOS unavailable");
    std::vector<std::uint8_t> data(size);
    if(GetSystemFirmwareTable(rsmb,0,data.data(),size)!=size)throw std::runtime_error("SMBIOS read failed");
    auto uuid=ohno::smbios_uuid(data);if(uuid.empty())throw std::runtime_error("SMBIOS UUID unavailable");
    return uuid;
}
identity get_identity(){
    const auto anchor=machine_anchor();
    PSECURITY_DESCRIPTOR sd=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;KA;;;SY)(A;;KA;;;BA)",SDDL_REVISION_1,&sd,nullptr))throw std::runtime_error("security descriptor");
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};reg_key key;
    LONG status=RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno\\Identity",0,nullptr,0,KEY_READ|KEY_WRITE,&sa,&key.h,nullptr);
    LocalFree(sd);if(status!=ERROR_SUCCESS)throw std::runtime_error("identity key");
    const std::string stored=utf8(read_string(key.h,L"Credentials"));
    if(stored.size()==130&&stored[32]==':'&&stored[65]==':'&&stored.substr(0,32)==anchor)
        return {stored.substr(33,32),stored.substr(66,64)};
    if(!clear_edge_policy())throw std::runtime_error("cannot clear copied browser policy");
    RegDeleteValueW(key.h,L"Policy"); // copied policies and grants must not follow cloned credentials
    auto newid=random_hex(16),newkey=random_hex(32);
    // A single registry value avoids persisting a partial id/key/anchor update.
    write_string(key.h,L"Credentials",wide_ascii(anchor+":"+newid+":"+newkey));
    return {newid,newkey};
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
    if(p.at("program_hashes").type!=ohno_json::value::kind::array||p.at("grants").type!=ohno_json::value::kind::array||p.at("web_domains").type!=ohno_json::value::kind::array||p.at("program_names").type!=ohno_json::value::kind::array)throw std::runtime_error("invalid policy");
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
    std::map<std::string,ULONGLONG> last_request;
    std::set<std::string> queued;
    while(WaitForSingleObject(stop_event,0)==WAIT_TIMEOUT){
        try{
            auto server=get_server();if(server.empty())throw std::runtime_error("server URL not configured");
            auto ident=get_identity();auto policy_text=cached_policy();bool online=false;
            auto h=L"X-Ohno-Device: "+wide_ascii(ident.id)+L"\r\nX-Ohno-Key: "+wide_ascii(ident.key)+L"\r\n";
            try{
                wchar_t name[MAX_COMPUTERNAME_LENGTH+1]{};DWORD n=MAX_COMPUTERNAME_LENGTH+1;
                std::wstring pc=GetComputerNameW(name,&n)?std::wstring(name,n):L"unknown";
                std::string data="{\"id\":"+quoted(ident.id)+",\"key\":"+quoted(ident.key)+",\"name\":"+quoted(utf8(pc))+"}";
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
                if(!apply_edge_policy(domains))debug(L"ohno: Edge policy update failed\n");
                std::vector<std::string> names;for(const auto& item:name_rules.items)if(item.type==ohno_json::value::kind::string)names.push_back(item.text);
                std::vector<std::string> allowed;
                std::vector<std::string> blocked;for(const auto& item:rules.items)if(item.type==ohno_json::value::kind::string&&item.text.size()==64)blocked.push_back(item.text);
                if(online)for(const auto& grant:grants.items){
                    const auto& kind=grant.at("kind");const auto& object=grant.at("object");const auto& expiry=grant.at("expires");
                    if(kind.type==ohno_json::value::kind::string&&kind.text=="application"&&object.type==ohno_json::value::kind::string&&expiry.type==ohno_json::value::kind::number){
                        try{if(std::stoll(expiry.text)>static_cast<long long>(std::time(nullptr)))allowed.push_back(object.text);}catch(const std::exception&){}
                    }
                }
                for(const auto& hash:stop_matching_processes(blocked,names,allowed)){
                    auto now=GetTickCount64();auto it=last_request.find(hash);
                    if(it==last_request.end()||now-it->second>=60000){last_request[hash]=now;queued.insert(hash);}
                }
            }
            if(online){
                for(auto it=queued.begin();it!=queued.end();){
                    try{auto body="{\"kind\":\"application\",\"object\":"+quoted(*it)+"}";
                        auto response=request(server,L"POST",L"/api/device/request",h+L"Content-Type: application/json\r\n",body);
                        if(response.status==201)it=queued.erase(it);else break;
                    }catch(const std::exception&){break;}
                }
            }
        }catch(const std::exception&){debug(L"ohno: service iteration failed\n");}
        if(WaitForSingleObject(stop_event,15000)!=WAIT_TIMEOUT)break;
    }
}
