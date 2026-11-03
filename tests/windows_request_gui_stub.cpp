// Linked only into the disposable GUI fixture, never a production binary.
// Control objects are process-specific and contain no credential bytes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <cassert>
#include <chrono>
#include <future>
#include "../windows/request_client.hpp"
#include "../windows/request_io.hpp"
namespace {
struct handle {HANDLE value=nullptr;~handle(){if(value)CloseHandle(value);}};
struct wipe {std::string& value;~wipe(){if(!value.empty())SecureZeroMemory(value.data(),value.size());}};
std::wstring name(const wchar_t* suffix){return L"Local\\OhnoRequestGuiTest-"+std::to_wstring(GetCurrentProcessId())+suffix;}
}
std::string send_teacher_request(std::string& message,HANDLE cancel,DWORD){
    wipe secret{message};
    handle calls{OpenSemaphoreW(SEMAPHORE_MODIFY_STATE,FALSE,name(L"-calls").c_str())};
    handle finish{OpenEventW(SYNCHRONIZE,FALSE,name(L"-finish").c_str())};
    handle timeout{OpenEventW(SYNCHRONIZE,FALSE,name(L"-timeout").c_str())};
    if(!calls.value||!finish.value||!timeout.value)return "unavailable";
    handle real{OpenEventW(SYNCHRONIZE,FALSE,name(L"-real-io").c_str())};
    if(real.value&&WaitForSingleObject(real.value,0)==WAIT_OBJECT_0){
        const auto pipe_name=L"\\\\.\\pipe\\OhnoGuiCloseIo-"+std::to_wstring(GetCurrentProcessId());
        ohno_request_io::handle server{CreateNamedPipeW(pipe_name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,1024,1024,0,nullptr)};
        assert(server.value!=INVALID_HANDLE_VALUE);
        ohno_request_io::handle client{CreateFileW(pipe_name.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr)};
        assert(client.value!=INVALID_HANDLE_VALUE);
        assert(ConnectNamedPipe(server.value,nullptr)||GetLastError()==ERROR_PIPE_CONNECTED);
        auto result=std::async(std::launch::async,[&]{return ohno_request_io::exchange(client.value,message,cancel,25000);});
        char request[1024]{};DWORD count=0;assert(ReadFile(server.value,request,sizeof(request),&count,nullptr)&&count>0);
        SecureZeroMemory(request,sizeof(request));
        assert(result.wait_for(std::chrono::milliseconds(50))==std::future_status::timeout);
        // Only announce after actual bytes arrived and no reply is supplied.
        // The window's Close now cancels/drains real outstanding pipe I/O.
        ReleaseSemaphore(calls.value,1,nullptr);
        return result.get();
    }
    ReleaseSemaphore(calls.value,1,nullptr);
    HANDLE waits[]{cancel,finish.value,timeout.value};const auto result=WaitForMultipleObjects(3,waits,FALSE,10000);
    // Simulate delayed I/O cancellation completion. UI must remain responsive,
    // reject duplicate submits, and be safe to close while this owner lives.
    if(result==WAIT_OBJECT_0){Sleep(200);return "cancelled";}
    return result==WAIT_OBJECT_0+1?"accepted":"timeout";
}
