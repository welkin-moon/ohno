#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "installed_payload.hpp"
#include "update_configuration.hpp"
int WINAPI wWinMain(HINSTANCE,HINSTANCE,LPWSTR,int){
    try {
        const auto exe=ohno::installed_request_helper(ohno::service_directory(),ohno::installed_release_key());
        auto command=L"\""+exe+L"\"";STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION child{};
        if(!CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&startup,&child))throw std::runtime_error("request helper");
        CloseHandle(child.hThread);CloseHandle(child.hProcess);return 0;
    }catch(...){MessageBoxW(nullptr,L"Ohno 请求工具不可用。请联系教师或学校 IT 检查安装。",L"Ohno",MB_OK|MB_ICONERROR);return 1;}
}
