#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <cstdio>
#include <string>
#include "../windows/network_filter.hpp"
int launch(const std::wstring& path,unsigned port){
 std::wstring cmd=L"\""+path+L"\" "+std::to_wstring(port);STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
 if(!CreateProcessW(path.c_str(),cmd.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi))return -1;
 CloseHandle(pi.hThread);if(WaitForSingleObject(pi.hProcess,5000)!=WAIT_OBJECT_0){TerminateProcess(pi.hProcess,9);CloseHandle(pi.hProcess);return -1;}
 DWORD code=0;GetExitCodeProcess(pi.hProcess,&code);CloseHandle(pi.hProcess);return static_cast<int>(code);
}
int main(){
 WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data))return 1;
 SOCKET listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(listener==INVALID_SOCKET)return 2;
 sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=0;
 if(bind(listener,reinterpret_cast<sockaddr*>(&a),sizeof(a))||listen(listener,4))return 3;
 int size=sizeof(a);if(getsockname(listener,reinterpret_cast<sockaddr*>(&a),&size))return 4;unsigned port=ntohs(a.sin_port);
 wchar_t buffer[32768]{};DWORD n=GetFullPathNameW(L"network-target.exe",32768,buffer,nullptr);if(!n||n>=32768)return 5;
 std::wstring path(buffer,n);std::string token(64,'a');
 if(launch(path,port)!=0)return 6;
 NetworkFilter filter;if(!filter.available()||!filter.register_untrusted(path,token))return 7;
 if(launch(path,port)==0)return 8;
 filter.apply_grants({token});if(launch(path,port)!=0)return 9;
 filter.apply_grants({});if(launch(path,port)==0)return 10;
 closesocket(listener);WSACleanup();std::puts("WFP outbound block and grant test passed");return 0;
}
