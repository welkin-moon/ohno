#pragma once
#include <windows.h>
#include <string>

// Internal transport only. The public client must authenticate the connected
// pipe owner before calling this; it is also exercised with disposable pipes.
namespace ohno_request_io {
struct handle {
    HANDLE value=nullptr;
    ~handle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
};
struct wipe {
    std::string& value;
    ~wipe(){if(!value.empty())SecureZeroMemory(value.data(),value.size());}
};
enum class outcome {complete,cancelled,timeout,unavailable};
inline bool cancelled(HANDLE cancel){return cancel&&WaitForSingleObject(cancel,0)!=WAIT_TIMEOUT;}
inline outcome transfer(HANDLE pipe,HANDLE event,HANDLE cancel,ULONGLONG deadline,
                        void* buffer,DWORD size,bool write,DWORD& count){
    count=0;
    if(cancelled(cancel))return outcome::cancelled;
    const auto now=GetTickCount64();
    if(now>=deadline)return outcome::timeout;
    ResetEvent(event);OVERLAPPED operation{};operation.hEvent=event;
    const BOOL immediate=write?WriteFile(pipe,buffer,size,&count,&operation):ReadFile(pipe,buffer,size,&count,&operation);
    if(immediate)return outcome::complete;
    if(GetLastError()!=ERROR_IO_PENDING)return outcome::unavailable;
    HANDLE waits[2]{cancel,event};const auto issued=GetTickCount64();
    const DWORD remaining=issued<deadline?static_cast<DWORD>(deadline-issued):0;
    const DWORD wait=cancel?WaitForMultipleObjects(2,waits,FALSE,remaining):WaitForSingleObject(event,remaining);
    if(wait==(cancel?WAIT_OBJECT_0+1:WAIT_OBJECT_0))
        return GetOverlappedResult(pipe,&operation,&count,FALSE)?outcome::complete:outcome::unavailable;
    // Cancellation is a request, not completion. Keep both OVERLAPPED and its
    // buffer alive until the kernel has finished, even if cancellation races
    // successful I/O. This is a worker-only wait: never block the GUI on drain.
    CancelIoEx(pipe,&operation);
    GetOverlappedResult(pipe,&operation,&count,TRUE);
    return wait==WAIT_TIMEOUT?outcome::timeout:cancelled(cancel)?outcome::cancelled:outcome::unavailable;
}
inline std::string failure(outcome result){
    return result==outcome::cancelled?"cancelled":result==outcome::timeout?"timeout":"unavailable";
}
inline std::string exchange(HANDLE pipe,std::string& message,HANDLE cancel,DWORD timeout_ms){
    wipe secret{message};handle event{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    if(!event.value)return "unavailable";
    const auto deadline=GetTickCount64()+timeout_ms;
    DWORD count=0;const auto size=static_cast<DWORD>(message.size());
    auto status=transfer(pipe,event.value,cancel,deadline,message.data(),size,true,count);
    SecureZeroMemory(message.data(),message.size());
    if(status!=outcome::complete)return failure(status);
    if(count!=size)return "unavailable";
    char reply[64]{};
    status=transfer(pipe,event.value,cancel,deadline,reply,sizeof(reply),false,count);
    if(status!=outcome::complete)return failure(status);
    const std::string result(reply,count);
    if(result!="accepted"&&result!="denied"&&result!="invalid")return "unavailable";
    // An acknowledgement is flow control, not authorization. A known response
    // remains known if Cancel/timeout races this final best-effort write.
    char ack='1';transfer(pipe,event.value,cancel,deadline,&ack,1,true,count);
    return result;
}
}
