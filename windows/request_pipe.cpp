#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <utility>
#include "request_pipe.hpp"
#include "../src/policy.hpp"
namespace {
struct handle{HANDLE h=nullptr;~handle(){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);}};
}
RequestPipe::RequestPipe(HANDLE stop,std::function<std::string(const std::string&)> callback):stop_(stop),callback_(std::move(callback)),worker_(&RequestPipe::serve,this){}
RequestPipe::~RequestPipe(){if(worker_.joinable())worker_.join();}
void RequestPipe::serve(){
    PSECURITY_DESCRIPTOR sd=nullptr;
    // Authenticated local users can read/write their request but cannot create server instances.
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;0x12019B;;;AU)",SDDL_REVISION_1,&sd,nullptr))return;
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
    while(WaitForSingleObject(stop_,0)==WAIT_TIMEOUT){
        handle pipe{CreateNamedPipeW(L"\\\\.\\pipe\\OhnoWebsiteRequest",PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,1024,1024,0,&sa)};
        if(!pipe.h||pipe.h==INVALID_HANDLE_VALUE){if(WaitForSingleObject(stop_,1000)!=WAIT_TIMEOUT)break;continue;}
        handle event{CreateEventW(nullptr,TRUE,FALSE,nullptr)};if(!event.h)break;
        OVERLAPPED ov{};ov.hEvent=event.h;
        BOOL connected=ConnectNamedPipe(pipe.h,&ov);DWORD error=connected?ERROR_SUCCESS:GetLastError();
        if(!connected&&error==ERROR_IO_PENDING){HANDLE waits[2]{stop_,event.h};if(WaitForMultipleObjects(2,waits,FALSE,5000)!=WAIT_OBJECT_0+1){CancelIoEx(pipe.h,&ov);WaitForSingleObject(event.h,INFINITE);continue;}DWORD n=0;if(!GetOverlappedResult(pipe.h,&ov,&n,FALSE))continue;}
        else if(!connected&&error!=ERROR_PIPE_CONNECTED)continue;
        ResetEvent(event.h);OVERLAPPED read{};read.hEvent=event.h;char buffer[1024]{};DWORD count=0;
        BOOL ok=ReadFile(pipe.h,buffer,sizeof(buffer),&count,&read);error=ok?ERROR_SUCCESS:GetLastError();
        if(!ok&&error==ERROR_IO_PENDING){HANDLE waits[2]{stop_,event.h};if(WaitForMultipleObjects(2,waits,FALSE,5000)!=WAIT_OBJECT_0+1){CancelIoEx(pipe.h,&read);WaitForSingleObject(event.h,INFINITE);continue;}ok=GetOverlappedResult(pipe.h,&read,&count,FALSE);}
        std::string result="invalid";
        if(ok&&count>2&&count<=sizeof(buffer)){
            std::string payload(buffer,count);
            if((payload.rfind("W:",0)==0&&ohno::valid_hostname(payload.substr(2)))||(payload.rfind("U:",0)==0&&payload.size()<=514)){
                try{result=callback_(payload);}catch(...){result="unavailable";}
            }
            SecureZeroMemory(payload.data(),payload.size());
        }
        SecureZeroMemory(buffer,sizeof(buffer));
        ResetEvent(event.h);OVERLAPPED write{};write.hEvent=event.h;DWORD sent=0;
        ok=WriteFile(pipe.h,result.data(),static_cast<DWORD>(result.size()),&sent,&write);error=ok?ERROR_SUCCESS:GetLastError();
        if(!ok&&error==ERROR_IO_PENDING){HANDLE waits[2]{stop_,event.h};if(WaitForMultipleObjects(2,waits,FALSE,5000)!=WAIT_OBJECT_0+1){CancelIoEx(pipe.h,&write);WaitForSingleObject(event.h,INFINITE);}else GetOverlappedResult(pipe.h,&write,&sent,FALSE);}
        // Wait briefly for the client to acknowledge its response; do not use
        // FlushFileBuffers, which can block indefinitely on an untrusted client.
        ResetEvent(event.h);OVERLAPPED ack{};ack.hEvent=event.h;char byte=0;DWORD received=0;
        ok=ReadFile(pipe.h,&byte,1,&received,&ack);error=ok?ERROR_SUCCESS:GetLastError();
        if(!ok&&error==ERROR_IO_PENDING){HANDLE waits[2]{stop_,event.h};if(WaitForMultipleObjects(2,waits,FALSE,5000)!=WAIT_OBJECT_0+1){CancelIoEx(pipe.h,&ack);WaitForSingleObject(event.h,INFINITE);}else GetOverlappedResult(pipe.h,&ack,&received,FALSE);}
        DisconnectNamedPipe(pipe.h);
    }
    LocalFree(sd);
}
