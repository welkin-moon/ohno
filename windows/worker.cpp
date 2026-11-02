#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cwchar>
#include <limits>
#include "agent.hpp"
#include "../src/update_health.hpp"
namespace {
std::uint64_t number(const wchar_t* text){if(!text||!*text)throw std::runtime_error("worker argument");std::uint64_t result=0;
    for(auto p=text;*p;++p){if(*p<L'0'||*p>L'9'||result>((std::numeric_limits<std::uint64_t>::max)()-(*p-L'0'))/10)throw std::runtime_error("worker argument");result=result*10+(*p-L'0');}return result;}
std::string ascii(const wchar_t* text){std::string result;for(auto p=text;*p;++p){if(*p>127)throw std::runtime_error("worker argument");result+=static_cast<char>(*p);}return result;}
bool system_token(){HANDLE token=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return false;
    alignas(TOKEN_USER) unsigned char data[1024]{};DWORD size=0;bool valid=GetTokenInformation(token,TokenUser,data,sizeof(data),&size)!=FALSE;
    if(valid)valid=IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(data)->User.Sid,WinLocalSystemSid)!=FALSE;CloseHandle(token);return valid;}
}
int wmain(int argc,wchar_t** argv){
    try{
        if(argc!=8||std::wcscmp(argv[1],L"--worker")||!system_token())return 2;
        HANDLE stop=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(number(argv[2]))),
            pipe=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(number(argv[3])));
        DWORD flags=0;if(!GetHandleInformation(stop,&flags)||!(flags&HANDLE_FLAG_INHERIT)||
            !GetHandleInformation(pipe,&flags)||!(flags&HANDLE_FLAG_INHERIT)||GetFileType(pipe)!=FILE_TYPE_PIPE)return 2;
        ohno::UpdateHealth proof{ascii(argv[4]),{number(argv[5]),ascii(argv[6]),ascii(argv[7])},1};
        const auto document=ohno::serialize_update_health(proof);bool sent=false;
        run_agent(stop,[&]{if(!sent){DWORD written=0;sent=WriteFile(pipe,document.data(),static_cast<DWORD>(document.size()),&written,nullptr)&&written==document.size();if(sent){CloseHandle(pipe);pipe=nullptr;}}});
        if(pipe)CloseHandle(pipe);CloseHandle(stop);return 0;
    }catch(...){return 1;}
}
