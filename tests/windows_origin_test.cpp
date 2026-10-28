#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include "../windows/monitor.hpp"
int main(){
 wchar_t path[32768]{};DWORD n=GetFullPathNameW(L"test-target.exe",32768,path,nullptr);if(!n||n>=32768)return 1;
 std::wstring stream=std::wstring(path)+L":Zone.Identifier";
 HANDLE f=CreateFileW(stream.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);if(f==INVALID_HANDLE_VALUE)return 2;
 const char data[]="[ZoneTransfer]\r\nZoneId=3\r\n";DWORD written=0;BOOL ok=WriteFile(f,data,sizeof(data)-1,&written,nullptr);CloseHandle(f);if(!ok)return 3;
 wchar_t cmd[]=L"\"test-target.exe\"";STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
 if(!CreateProcessW(path,cmd,nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)){DeleteFileW(stream.c_str());return 4;}
 CloseHandle(pi.hThread);Sleep(500);auto observed=observe_untrusted_programs();bool found=false;
 for(const auto& entry:observed)if(entry.pid==pi.dwProcessId&&!entry.hash.empty())found=true;
 TerminateProcess(pi.hProcess,0);CloseHandle(pi.hProcess);DeleteFileW(stream.c_str());
 if(!found)return 5;std::puts("download origin detection test passed");return 0;
}
