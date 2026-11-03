#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include "request_client.hpp"
#include "request_io.hpp"
#pragma comment(lib,"advapi32.lib")
namespace {
struct handle {HANDLE value=INVALID_HANDLE_VALUE;~handle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}};
struct local_memory {HLOCAL value=nullptr;~local_memory(){if(value)LocalFree(value);}};
struct wipe {std::string& value;~wipe(){if(!value.empty())SecureZeroMemory(value.data(),value.size());}};
bool system_owned(HANDLE pipe){
    PSID owner=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    const DWORD result=GetSecurityInfo(pipe,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION,&owner,nullptr,nullptr,nullptr,&descriptor);
    local_memory memory{descriptor};
    return result==ERROR_SUCCESS&&owner&&IsValidSid(owner)&&IsWellKnownSid(owner,WinLocalSystemSid);
}
}
std::string send_teacher_request(std::string& message,HANDLE cancel,DWORD timeout_ms){
    wipe secret{message};
    if(message.empty()||message.size()>1024||timeout_ms<50||timeout_ms>30000)return "invalid";
    if(ohno_request_io::cancelled(cancel))return "cancelled";
    // Request individual rights, not GENERIC_WRITE (which includes permission
    // to create additional named-pipe server instances). READ_CONTROL permits
    // checking the owner on THIS connected handle before any secret is sent.
    handle pipe{CreateFileW(L"\\\\.\\pipe\\OhnoWebsiteRequest",
        FILE_READ_DATA|FILE_WRITE_DATA|SYNCHRONIZE|READ_CONTROL,0,nullptr,OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr)};
    if(pipe.value==INVALID_HANDLE_VALUE){const DWORD error=GetLastError();return error==ERROR_FILE_NOT_FOUND||error==ERROR_PIPE_BUSY?"notready":"unavailable";}
    if(!system_owned(pipe.value))return "untrusted";
    // The service never impersonates clients; identification-only SQOS also
    // prevents a name-squatting server from using the caller's security token.
    return ohno_request_io::exchange(pipe.value,message,cancel,timeout_ms);
}
