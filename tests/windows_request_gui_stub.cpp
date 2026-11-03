// Linked only into the disposable GUI fixture, never a production binary.
// Control objects are process-specific and contain no credential bytes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include "../windows/request_client.hpp"
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
    ReleaseSemaphore(calls.value,1,nullptr);
    HANDLE waits[]{cancel,finish.value,timeout.value};const auto result=WaitForMultipleObjects(3,waits,FALSE,10000);
    // Simulate delayed I/O cancellation completion. UI must remain responsive,
    // reject duplicate submits, and be safe to close while this owner lives.
    if(result==WAIT_OBJECT_0){Sleep(200);return "cancelled";}
    return result==WAIT_OBJECT_0+1?"accepted":"timeout";
}
