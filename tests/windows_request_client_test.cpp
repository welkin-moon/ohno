// Disposable user-owned fake pipe. Read raw bytes, not a parsed callback, so a
// zero-byte assertion cannot accidentally pass after malformed input or STOP.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <cassert>
#include <cstdio>
#include <future>
#include <string>
#include "../windows/request_client.hpp"
int main(){
    HANDLE pipe=CreateNamedPipeW(L"\\\\.\\pipe\\OhnoWebsiteRequest",
        PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,
        1,1024,1024,0,nullptr);
    assert(pipe!=INVALID_HANDLE_VALUE);
    PSID owner=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    assert(GetSecurityInfo(pipe,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION,&owner,nullptr,nullptr,nullptr,&descriptor)==ERROR_SUCCESS);
    assert(owner&&!IsWellKnownSid(owner,WinLocalSystemSid));LocalFree(descriptor);
    HANDLE event=CreateEventW(nullptr,TRUE,FALSE,nullptr);assert(event);
    OVERLAPPED connect{};connect.hEvent=event;
    assert(!ConnectNamedPipe(pipe,&connect)&&GetLastError()==ERROR_IO_PENDING);
    auto client=std::async(std::launch::async,[]{
        std::string secret="U:2468";const auto result=send_teacher_request(secret);
        assert(secret.find_first_not_of('\0')==std::string::npos);return result;
    });
    assert(WaitForSingleObject(event,3000)==WAIT_OBJECT_0);
    DWORD count=0;assert(GetOverlappedResult(pipe,&connect,&count,FALSE));
    ResetEvent(event);OVERLAPPED read{};read.hEvent=event;
    char raw[1024]{};count=0;BOOL ok=ReadFile(pipe,raw,sizeof(raw),&count,&read);
    DWORD error=ok?ERROR_SUCCESS:GetLastError();
    if(!ok&&error==ERROR_IO_PENDING){
        assert(WaitForSingleObject(event,3000)==WAIT_OBJECT_0);
        ok=GetOverlappedResult(pipe,&read,&count,FALSE);error=ok?ERROR_SUCCESS:GetLastError();
    }
    // The client must close without a write. If it sent even a malformed PIN
    // prefix, the connected server receives bytes and this assertion fails.
    assert(!ok&&count==0&&(error==ERROR_BROKEN_PIPE||error==ERROR_NO_DATA));
    assert(client.get()=="untrusted");
    CloseHandle(event);CloseHandle(pipe);
    std::string missing="U:2468";
    assert(send_teacher_request(missing)=="notready");
    assert(missing.find_first_not_of('\0')==std::string::npos);
    std::puts("User-owned pipe received zero raw PIN bytes; refusal/absence buffers wiped");
}
