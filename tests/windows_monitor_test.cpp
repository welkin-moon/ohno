#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <string>
#include "../windows/monitor.hpp"
int main(int argc,char** argv){
    if(argc!=2)return 2;
    wchar_t command[]=L"\"test-target.exe\"";
    STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
    if(!CreateProcessW(L"test-target.exe",command,nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi))return 3;
    CloseHandle(pi.hThread);
    Sleep(500);
    auto result=stop_matching_processes({std::string(argv[1])});
    bool dead=WaitForSingleObject(pi.hProcess,2000)==WAIT_OBJECT_0;
    if(!dead)TerminateProcess(pi.hProcess,1);
    CloseHandle(pi.hProcess);
    if(!dead||result.empty()){std::fprintf(stderr,"monitor did not stop test target\n");return 4;}
    std::puts("monitor test passed");return 0;
}
