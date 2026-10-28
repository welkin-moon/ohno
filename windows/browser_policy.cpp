#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "browser_policy.hpp"
#include "../src/policy.hpp"
namespace {
struct key { HKEY h=nullptr; ~key(){if(h)RegCloseKey(h);} };
bool open_or_create(HKEY root,const std::wstring& path,key& k){return RegCreateKeyExW(root,path.c_str(),0,nullptr,0,KEY_READ|KEY_WRITE,nullptr,&k.h,nullptr)==ERROR_SUCCESS;}
std::map<std::wstring,std::wstring> values(HKEY key,bool& ok){
    std::map<std::wstring,std::wstring> out;
    for(DWORD i=0;;++i){
        wchar_t name[256]{};wchar_t value[1024]{};DWORD name_len=256,size=sizeof(value),type=0;
        LONG code=RegEnumValueW(key,i,name,&name_len,nullptr,&type,reinterpret_cast<BYTE*>(value),&size);
        if(code==ERROR_NO_MORE_ITEMS)break;
        if(code!=ERROR_SUCCESS||type!=REG_SZ||size%sizeof(wchar_t)||size<sizeof(wchar_t)||size>sizeof(value)||value[size/sizeof(wchar_t)-1]!=0){ok=false;break;}
        out.emplace(std::wstring(name,name_len),std::wstring(value));
    }return out;
}
bool write(HKEY key,const std::wstring& name,const std::wstring& value){return RegSetValueExW(key,name.c_str(),0,REG_SZ,reinterpret_cast<const BYTE*>(value.c_str()),static_cast<DWORD>((value.size()+1)*sizeof(wchar_t)))==ERROR_SUCCESS;}
std::wstring ascii(const std::string& s){return std::wstring(s.begin(),s.end());}
}
bool apply_browser_policy_at(HKEY root,const std::wstring& target,const std::wstring& tracker,const std::vector<std::string>& domains){
    if(domains.size()>1000)return false;
    std::set<std::wstring> wanted;
    for(const auto& d:domains){if(d!="file://*"&&!ohno::valid_hostname(d)&&!(d.size()>1&&d[0]=='.'&&ohno::valid_hostname(d.substr(1))))return false;wanted.insert(ascii(d));}
    key p,t;if(!open_or_create(root,target,p)||!open_or_create(root,tracker,t))return false;
    bool ok=true;auto current=values(p.h,ok);auto owned=values(t.h,ok);if(!ok)return false;
    for(const auto& item:owned){
        auto found=current.find(item.first);
        bool matches=found!=current.end()&&found->second==item.second;
        if(matches&&wanted.count(item.second))continue;
        if(matches){if(RegDeleteValueW(p.h,item.first.c_str())!=ERROR_SUCCESS)return false;current.erase(found);}
        if(RegDeleteValueW(t.h,item.first.c_str())!=ERROR_SUCCESS)return false;
    }
    std::set<std::wstring> present;for(const auto& item:current)present.insert(item.second);
    for(const auto& domain:wanted){
        if(present.count(domain))continue;
        std::wstring slot;
        for(unsigned i=1;i<=1000;++i){auto name=std::to_wstring(i);if(current.count(name)==0){slot=name;break;}}
        if(slot.empty())return false;
        // Record ownership before changing the shared target, so a crash is recoverable.
        if(!write(t.h,slot,domain))return false;
        if(!write(p.h,slot,domain)){RegDeleteValueW(t.h,slot.c_str());return false;}
        current.emplace(slot,domain);present.insert(domain);
    }
    return true;
}
bool apply_edge_policy(const std::vector<std::string>& domains){return apply_browser_policy_at(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Policies\\Microsoft\\Edge\\URLBlocklist",L"SOFTWARE\\Ohno\\BrowserRules\\Edge",domains);}
bool clear_edge_policy(){return apply_edge_policy({});}
bool apply_edge_allow_policy(const std::vector<std::string>& domains){return apply_browser_policy_at(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Policies\\Microsoft\\Edge\\URLAllowlist",L"SOFTWARE\\Ohno\\BrowserRules\\EdgeAllow",domains);}
bool clear_edge_allow_policy(){return apply_edge_allow_policy({});}
