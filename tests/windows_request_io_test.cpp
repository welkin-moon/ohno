// Transport-only fixtures; no SYSTEM token, service, root store or teacher.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <future>
#include <string>
#include "../windows/request_io.hpp"
namespace {
using namespace ohno_request_io;
struct pair {
    handle server,client;
    pair(){
        static unsigned sequence=0;
        const auto name=L"\\\\.\\pipe\\OhnoRequestIoTest-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(++sequence);
        server.value=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,128,128,0,nullptr);
        assert(server.value!=INVALID_HANDLE_VALUE);
        client.value=CreateFileW(name.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);
        assert(client.value!=INVALID_HANDLE_VALUE);
        assert(ConnectNamedPipe(server.value,nullptr)||GetLastError()==ERROR_PIPE_CONNECTED);
    }
};
void erased(const std::string& s){assert(s.find_first_not_of('\0')==std::string::npos);}
void within(ULONGLONG start){assert(GetTickCount64()-start<3000);}
}
int main(){
    {pair pipe;std::string text="U:2468";
     auto result=std::async(std::launch::async,[&]{return exchange(pipe.client.value,text,nullptr,2000);});
     char raw[64]{};DWORD count=0;assert(ReadFile(pipe.server.value,raw,sizeof(raw),&count,nullptr)&&count==6);
     assert(std::string(raw,count)=="U:2468");assert(WriteFile(pipe.server.value,"accepted",8,&count,nullptr)&&count==8);
     assert(ReadFile(pipe.server.value,raw,sizeof(raw),&count,nullptr)&&count==1&&raw[0]=='1');
     assert(result.get()=="accepted");erased(text);}
    {pair pipe;std::string text="W:test.example";const auto start=GetTickCount64();
     assert(exchange(pipe.client.value,text,nullptr,100)=="timeout");within(start);erased(text);}
    {pair pipe;handle cancel{CreateEventW(nullptr,TRUE,FALSE,nullptr)};assert(cancel.value);
     std::string text="U:2468";auto result=std::async(std::launch::async,[&]{return exchange(pipe.client.value,text,cancel.value,5000);});
     char raw[64]{};DWORD count=0;assert(ReadFile(pipe.server.value,raw,sizeof(raw),&count,nullptr)&&count==6);
     const auto start=GetTickCount64();SetEvent(cancel.value);assert(result.get()=="cancelled");within(start);erased(text);}
    {pair pipe;handle cancel{CreateEventW(nullptr,TRUE,TRUE,nullptr)};assert(cancel.value);
     std::string text="U:2468";assert(exchange(pipe.client.value,text,cancel.value,5000)=="cancelled");erased(text);
     DWORD available=0;assert(PeekNamedPipe(pipe.server.value,nullptr,0,nullptr,&available,nullptr)&&available==0);}
    // Force pending write independently of the reply phase; the server never
    // reads this large nonsecret buffer. Cancellation must drain before return.
    for(bool timeout:{false,true}){
        pair pipe;handle cancel{CreateEventW(nullptr,TRUE,FALSE,nullptr)},event{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
        assert(cancel.value&&event.value);std::string bytes(8*1024*1024,'x');DWORD count=0;
        const auto start=GetTickCount64();
        auto result=std::async(std::launch::async,[&]{return transfer(pipe.client.value,event.value,cancel.value,
            GetTickCount64()+(timeout?100:5000),bytes.data(),static_cast<DWORD>(bytes.size()),true,count);});
        assert(result.wait_for(std::chrono::milliseconds(25))==std::future_status::timeout);
        if(!timeout)SetEvent(cancel.value);
        assert(result.get()==(timeout?outcome::timeout:outcome::cancelled));within(start);
    }
    // Reply completion and cancellation can win in either order. Neither
    // result permits automatic replay; the exchange must always drain/wipe.
    for(int i=0;i<24;++i){
        pair pipe;handle cancel{CreateEventW(nullptr,TRUE,FALSE,nullptr)};assert(cancel.value);
        std::string text="U:2468";
        auto result=std::async(std::launch::async,[&]{return exchange(pipe.client.value,text,cancel.value,2000);});
        char raw[64]{};DWORD count=0;assert(ReadFile(pipe.server.value,raw,sizeof(raw),&count,nullptr)&&count==6);
        assert(WriteFile(pipe.server.value,"accepted",8,&count,nullptr)&&count==8);
        if(i%2)Sleep(1);
        SetEvent(cancel.value);const auto outcome=result.get();
        assert(outcome=="accepted"||outcome=="cancelled");erased(text);
        DWORD available=0;assert(PeekNamedPipe(pipe.server.value,nullptr,0,nullptr,&available,nullptr)&&available<=1);
    }
    std::puts("Overlapped request: reply, read/write cancellation, timeout, pre-cancel zero bytes, 24 reply/cancel races and buffer drain passed");
}
