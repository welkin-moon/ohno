// Disposable user-owned fake pipe. Never installs a service or changes a token.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atomic>
#include <cassert>
#include <cstdio>
#include <string>
#include "../windows/request_pipe.hpp"
#include "../windows/request_client.hpp"
int main(){
    HANDLE token=nullptr;assert(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));
    alignas(TOKEN_USER) BYTE info[sizeof(TOKEN_USER)+SECURITY_MAX_SID_SIZE]{};DWORD bytes=0;
    assert(GetTokenInformation(token,TokenUser,info,sizeof(info),&bytes));
    assert(!IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(info)->User.Sid,WinLocalSystemSid));CloseHandle(token);
    HANDLE stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);assert(stop);
    std::atomic<unsigned> received{0};
    {
        RequestPipe fake(stop,[&](const std::string&){++received;return "accepted";});
        const auto deadline=GetTickCount64()+5000;
        while(!fake.available()&&GetTickCount64()<deadline)Sleep(10);
        assert(fake.available());
        std::string secret="U:2468";const auto began=GetTickCount64();
        assert(send_teacher_request(secret)=="untrusted");
        assert(secret.find_first_not_of('\0')==std::string::npos);
        assert(GetTickCount64()-began<2000);
        SetEvent(stop);
    }
    assert(received.load()==0);CloseHandle(stop);
    std::string missing="U:2468";
    assert(send_teacher_request(missing)=="notready");
    assert(missing.find_first_not_of('\0')==std::string::npos);
    std::puts("User-owned pipe refused before classroom PIN bytes; message buffers wiped");
}
