#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>
#include "update_configuration.hpp"
namespace {
struct Key{HKEY h=nullptr;~Key(){if(h)RegCloseKey(h);}};
struct Text{std::vector<wchar_t> data;~Text(){if(!data.empty())SecureZeroMemory(data.data(),data.size()*sizeof(wchar_t));}};
std::wstring value(HKEY key,const wchar_t* name){DWORD type=0,size=0;
    if(RegQueryValueExW(key,name,nullptr,&type,nullptr,&size)!=ERROR_SUCCESS||type!=REG_SZ||size<2||size>65536||size%2)return {};
    Text buffer;buffer.data.resize(size/2+1,0);if(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE*>(buffer.data.data()),&size)!=ERROR_SUCCESS||type!=REG_SZ||size%2)return {};
    return std::wstring(buffer.data.data());}
std::string ascii(const std::wstring& s){std::string result;for(auto c:s){if(c>127)throw std::runtime_error("non-ASCII installation trust");result+=static_cast<char>(c);}return result;}
}
namespace ohno {
std::wstring service_directory(){std::vector<wchar_t> buffer(32768);const DWORD n=GetModuleFileNameW(nullptr,buffer.data(),static_cast<DWORD>(buffer.size()));
    if(!n||n>=buffer.size())throw std::runtime_error("service path");std::wstring path(buffer.data(),n);auto slash=path.find_last_of(L"\\/");if(slash==std::wstring::npos)throw std::runtime_error("service path");return path.substr(0,slash);}
std::string installed_release_key(){Key key;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&key.h)!=ERROR_SUCCESS)throw std::runtime_error("installation configuration");return ascii(value(key.h,L"ReleasePublicKey"));}
UpdateConnection installed_update_connection(){
    Key config,identity;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&config.h)!=ERROR_SUCCESS||
        RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno\\Identity",0,KEY_READ,&identity.h)!=ERROR_SUCCESS)throw std::runtime_error("installation identity");
    UpdateConnection result;result.server=value(config.h,L"ServerUrl");result.certificate_pem=ascii(value(config.h,L"TeacherCertificatePem"));result.release_public_key=ascii(value(config.h,L"ReleasePublicKey"));
    auto credentials=value(identity.h,L"Credentials");struct Wipe{std::wstring& s;~Wipe(){if(!s.empty())SecureZeroMemory(s.data(),s.size()*sizeof(wchar_t));}}wipe{credentials};
    const auto n=credentials.size();if(n<98||credentials[n-98]!=L':'||credentials[n-65]!=L':')throw std::runtime_error("installation identity");
    result.device_id.assign(credentials.begin()+static_cast<std::ptrdiff_t>(n-97),credentials.begin()+static_cast<std::ptrdiff_t>(n-65));
    result.device_key.assign(credentials.begin()+static_cast<std::ptrdiff_t>(n-64),credentials.end());return result;
}
}
