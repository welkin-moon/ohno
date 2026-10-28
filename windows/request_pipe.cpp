#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include "request_pipe.hpp"
#include "../src/policy.hpp"
namespace {
struct handle{HANDLE h=nullptr;~handle(){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);}};
}
RequestPipe::RequestPipe(HANDLE stop):stop_(stop),worker_(&RequestPipe::serve,this){}
RequestPipe::~RequestPipe(){if(worker_.joinable())worker_.join();}
std::vector<std::string> RequestPipe::take(){std::lock_guard<std::mutex> lock(mutex_);std::vector<std::string> out(pending_.begin(),pending_.end());pending_.clear();return out;}
void RequestPipe::serve(){
    PSECURITY_DESCRIPTOR sd=nullptr;
    // AU can write requests but cannot create a server instance (FILE_CREATE_PIPE_INSTANCE).
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;0x120002;;;AU)",SDDL_REVISION_1,&sd,nullptr))return;
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
    while(WaitForSingleObject(stop_,0)==WAIT_TIMEOUT){
        handle pipe{CreateNamedPipeW(L"\\\\.\\pipe\\OhnoWebsiteRequest",PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,0,1024,0,&sa)};
        if(!pipe.h||pipe.h==INVALID_HANDLE_VALUE){if(WaitForSingleObject(stop_,1000)!=WAIT_TIMEOUT)break;continue;}
        handle event{CreateEventW(nullptr,TRUE,FALSE,nullptr)};if(!event.h)break;
        OVERLAPPED ov{};ov.hEvent=event.h;
        BOOL connected=ConnectNamedPipe(pipe.h,&ov);DWORD error=connected?ERROR_SUCCESS:GetLastError();
        if(!connected&&error==ERROR_IO_PENDING){HANDLE waits[2]{stop_,event.h};if(WaitForMultipleObjects(2,waits,FALSE,5000)!=WAIT_OBJECT_0+1){CancelIoEx(pipe.h,&ov);WaitForSingleObject(event.h,INFINITE);continue;}DWORD n=0;if(!GetOverlappedResult(pipe.h,&ov,&n,FALSE))continue;}
        else if(!connected&&error!=ERROR_PIPE_CONNECTED)continue;
        ResetEvent(event.h);OVERLAPPED read{};read.hEvent=event.h;char buffer[254]{};DWORD count=0;
        BOOL ok=ReadFile(pipe.h,buffer,253,&count,&read);error=ok?ERROR_SUCCESS:GetLastError();
        if(!ok&&error==ERROR_IO_PENDING){HANDLE waits[2]{stop_,event.h};if(WaitForMultipleObjects(2,waits,FALSE,5000)!=WAIT_OBJECT_0+1){CancelIoEx(pipe.h,&read);WaitForSingleObject(event.h,INFINITE);continue;}ok=GetOverlappedResult(pipe.h,&read,&count,FALSE);}
        if(ok&&count>0&&count<=253){std::string domain(buffer,count);if(ohno::valid_hostname(domain)){std::lock_guard<std::mutex> lock(mutex_);if(pending_.size()<100)pending_.insert(domain);}}
        DisconnectNamedPipe(pipe.h);
    }
    LocalFree(sd);
}
