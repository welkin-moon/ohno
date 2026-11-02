// Test-only worker. Never linked into production payloads. All paths are under
// the caller's temporary directory; deliberately adversarial health responses.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cwchar>
#include <string>
#include "../src/update_health.hpp"
std::string narrow(const wchar_t* p){return {p,p+std::wcslen(p)};}
void log(const std::string& event){HANDLE f=CreateFileW(L"..\\..\\worker-events.log",FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(f==INVALID_HANDLE_VALUE)return;const auto line=std::to_string(GetCurrentProcessId())+" "+event+"\n";DWORD n=0;WriteFile(f,line.data(),static_cast<DWORD>(line.size()),&n,nullptr);FlushFileBuffers(f);CloseHandle(f);}
int wmain(int argc,wchar_t** argv){
    if(argc==2&&!std::wcscmp(argv[1],L"--descendant")){log("descendant");Sleep(INFINITE);return 0;}
    if(argc!=8||std::wcscmp(argv[1],L"--worker"))return 2;
    HANDLE stop=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(argv[2],nullptr,10))),
        pipe=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(argv[3],nullptr,10)));
    ohno::UpdateHealth proof{narrow(argv[4]),{std::wcstoull(argv[5],nullptr,10),narrow(argv[6]),narrow(argv[7])},1};
    const auto version=proof.revision.version;log("start "+std::to_string(proof.revision.sequence)+" "+version);
    if(version.find("exit")!=std::string::npos)return 9;
    if(version.find("restart")!=std::string::npos){HANDLE marker=CreateFileW(L"..\\..\\first-exit",GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(marker!=INVALID_HANDLE_VALUE){CloseHandle(marker);return 9;}}
    if(version.find("descendant")!=std::string::npos){wchar_t exe[32768];GetModuleFileNameW(nullptr,exe,32768);std::wstring command=L"\""+std::wstring(exe)+L"\" --descendant";STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
        if(CreateProcessW(exe,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)){CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}}
    if(version.find("nohealth")==std::string::npos){
        if(version.find("nonce")!=std::string::npos)proof.transaction=std::string(64,'f');
        if(version.find("revision")!=std::string::npos)++proof.revision.sequence;
        auto data=ohno::serialize_update_health(proof);
        if(version.find("zero")!=std::string::npos)data.replace(data.find("\"cycles\":1"),10,"\"cycles\":0");
        if(version.find("malformed")!=std::string::npos)data="{\n";
        if(version.find("oversize")!=std::string::npos)data=std::string(513,' ')+"\n";
        DWORD sent=0;WriteFile(pipe,data.data(),static_cast<DWORD>(data.size()),&sent,nullptr);log("proof "+version);
    }
    CloseHandle(pipe);WaitForSingleObject(stop,INFINITE);log("stop "+version);CloseHandle(stop);return 0;
}
