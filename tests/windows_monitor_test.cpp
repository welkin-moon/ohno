#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <string>
#include "../windows/monitor.hpp"
bool check(const std::string& hash,bool by_name,bool allow){
    wchar_t command[]=L"\"test-target.exe\"";
    STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
    if(!CreateProcessW(L"test-target.exe",command,nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi))return false;
    CloseHandle(pi.hThread);Sleep(500);
    std::vector<std::string> hashes=by_name?std::vector<std::string>{}:std::vector<std::string>{hash};
    std::vector<std::string> names=by_name?std::vector<std::string>{"test-target.exe"}:std::vector<std::string>{};
    std::vector<std::string> allowed=allow?std::vector<std::string>{hash}:std::vector<std::string>{};
    auto result=stop_matching_processes(hashes,names,allowed,pi.dwProcessId);
    bool dead=WaitForSingleObject(pi.hProcess,2000)==WAIT_OBJECT_0;
    if(!dead)TerminateProcess(pi.hProcess,1);
    CloseHandle(pi.hProcess);
    return allow?(!dead&&result.empty()):(dead&&!result.empty());
}
int main(int argc,char** argv){
    if(argc!=2)return 2;
    if(!check(argv[1],false,false)||!check(argv[1],true,false)||!check(argv[1],true,true)){
        std::fprintf(stderr,"monitor rule or approval test failed\n");return 4;
    }
    std::puts("monitor hash, name and approval tests passed");return 0;
}
