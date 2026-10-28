#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cassert>
#include <cstdio>
#include <string>
#include "../windows/browser_policy.hpp"
int main(){
 const std::wstring base=L"Software\\OhnoCiTest";
 RegDeleteTreeW(HKEY_CURRENT_USER,base.c_str());
 auto target=base+L"\\target",tracker=base+L"\\tracker";
 HKEY key=nullptr;assert(RegCreateKeyExW(HKEY_CURRENT_USER,target.c_str(),0,nullptr,0,KEY_ALL_ACCESS,nullptr,&key,nullptr)==ERROR_SUCCESS);
 const wchar_t existing[]=L"school.example";assert(RegSetValueExW(key,L"1",0,REG_SZ,reinterpret_cast<const BYTE*>(existing),sizeof(existing))==ERROR_SUCCESS);RegCloseKey(key);
 assert(apply_browser_policy_at(HKEY_CURRENT_USER,target,tracker,{"game.example"}));
 assert(apply_browser_policy_at(HKEY_CURRENT_USER,target,tracker,{"game.example","other.example"}));
 assert(apply_browser_policy_at(HKEY_CURRENT_USER,target,tracker,{"other.example"}));
 // A policy changed by another administrator must not be removed as ours.
 assert(RegOpenKeyExW(HKEY_CURRENT_USER,target.c_str(),0,KEY_WRITE,&key)==ERROR_SUCCESS);
 const wchar_t changed[]=L"managed-elsewhere.example";
 assert(RegSetValueExW(key,L"3",0,REG_SZ,reinterpret_cast<const BYTE*>(changed),sizeof(changed))==ERROR_SUCCESS);RegCloseKey(key);
 assert(apply_browser_policy_at(HKEY_CURRENT_USER,target,tracker,{}));
 assert(RegOpenKeyExW(HKEY_CURRENT_USER,target.c_str(),0,KEY_READ,&key)==ERROR_SUCCESS);DWORD count=0;assert(RegQueryInfoKeyW(key,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,&count,nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS);assert(count==2);
 wchar_t value[128]{};DWORD size=sizeof(value);assert(RegQueryValueExW(key,L"1",nullptr,nullptr,reinterpret_cast<BYTE*>(value),&size)==ERROR_SUCCESS);assert(std::wstring(value)==L"school.example");size=sizeof(value);assert(RegQueryValueExW(key,L"3",nullptr,nullptr,reinterpret_cast<BYTE*>(value),&size)==ERROR_SUCCESS);assert(std::wstring(value)==L"managed-elsewhere.example");RegCloseKey(key);
 assert(!apply_browser_policy_at(HKEY_CURRENT_USER,target,tracker,{"bad domain"}));
 RegDeleteTreeW(HKEY_CURRENT_USER,base.c_str());std::puts("browser policy tests passed");
}
