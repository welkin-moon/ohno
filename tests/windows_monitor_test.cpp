#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <string>
#include "../windows/monitor.hpp"
bool check(const std::string& hash,bool by_name,bool allow,bool stopped=false){
    wchar_t command[]=L"\"test-target.exe\"";
    STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
    if(!CreateProcessW(L"test-target.exe",command,nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi))return false;
    CloseHandle(pi.hThread);Sleep(500);
    std::vector<std::string> hashes=by_name?std::vector<std::string>{}:std::vector<std::string>{hash};
    std::vector<std::string> names=by_name?std::vector<std::string>{"test-target.exe"}:std::vector<std::string>{};
    std::vector<std::string> allowed=allow?std::vector<std::string>{hash}:std::vector<std::string>{};
    HANDLE stop=CreateEventW(nullptr,TRUE,stopped?TRUE:FALSE,nullptr);
    auto result=stop_matching_processes(hashes,names,allowed,pi.dwProcessId,stop);CloseHandle(stop);
    bool dead=WaitForSingleObject(pi.hProcess,2000)==WAIT_OBJECT_0;
    if(!dead)TerminateProcess(pi.hProcess,1);
    CloseHandle(pi.hProcess);
    return (allow||stopped)?(!dead&&result.empty()):(dead&&!result.empty());
}
int main(int argc,char** argv){
    if(argc!=2)return 2;
    if(!check(argv[1],false,false)||!check(argv[1],true,false)||!check(argv[1],true,true)||!check(argv[1],true,false,true)){
        std::fprintf(stderr,"monitor rule or approval test failed\n");return 4;
    }
    // A large PE overlay makes hashing deliberately unavailable. A matching
    // filename rule must still stop the process instead of silently allowing it.
    const wchar_t large[]=L"large-test-target.exe";
    if(!CopyFileW(L"test-target.exe",large,TRUE))return 5;
    HANDLE file=CreateFileW(large,GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);
    if(file==INVALID_HANDLE_VALUE){DeleteFileW(large);return 6;}
    LARGE_INTEGER size{};size.QuadPart=512LL*1024*1024+1;
    bool extended=SetFilePointerEx(file,size,nullptr,FILE_BEGIN)&&SetEndOfFile(file);
    CloseHandle(file);
    if(!extended){DeleteFileW(large);return 7;}
    wchar_t command[]=L"\"large-test-target.exe\"";
    STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
    if(!CreateProcessW(large,command,nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)){
        DeleteFileW(large);return 8;
    }
    CloseHandle(pi.hThread);Sleep(500);
    auto blocked=stop_matching_processes({}, {"large-test-target.exe"}, {}, pi.dwProcessId);
    bool dead=WaitForSingleObject(pi.hProcess,2000)==WAIT_OBJECT_0;
    if(!dead)TerminateProcess(pi.hProcess,1);
    WaitForSingleObject(pi.hProcess,5000);CloseHandle(pi.hProcess);DeleteFileW(large);
    if(!dead||blocked.size()!=1||!blocked[0].hash.empty())return 9;
    std::puts("monitor hash, name, unhashable image and approval tests passed");return 0;
}
