#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <thread>
#include <fstream>
#include <filesystem>
#include "../windows/update_runtime.hpp"
#include "../windows/worker_process.hpp"
namespace {
bool stop_after_poll=true,stop_after_rollback=false,saw_rollback=false;std::wstring fixture_root;unsigned crash=0,stop_at=0;HANDLE stop_event=nullptr;
void worker_point(unsigned p,DWORD pid){if(pid){std::ofstream out(std::filesystem::path(fixture_root+L"\\worker-events.log"),std::ios::app);out<<pid<<" constructor\n";}if(p==crash)ExitProcess(100+p);if(p==stop_at)SetEvent(stop_event);}
void point(unsigned p){if(p==crash)ExitProcess(100+p);if(p==9)saw_rollback=true;if(p==stop_at||(p==14&&stop_after_poll)||(p==2&&saw_rollback&&stop_after_rollback))SetEvent(stop_event);}
std::string text(const ohno_json::value& v,const char* name){return ohno::update_detail::text(v,name);}
std::wstring wide(const std::string& s){int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);if(n<=0)throw std::runtime_error("path");std::wstring w(n,L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),w.data(),n);return w;}
std::string file(const std::wstring& path){std::ifstream f(std::filesystem::path(path),std::ios::binary);if(!f)throw std::runtime_error("file");return {std::istreambuf_iterator<char>(f),{}};}
}
int main(){
    std::string input;std::getline(std::cin,input);std::thread timer;
    try{
        const auto v=ohno_json::parse(input);const auto root=wide(text(v,"root"));fixture_root=root;const auto key=text(v,"public_key");
        if(v.at("initialize").boolean){ohno::WindowsUpdateJournal disk(root);auto initial=ohno::stage_initial_payload(disk,file(wide(text(v,"baseline"))));if(disk.initialize(ohno::initial_update_journal(initial))!=ohno::JournalWrite::Durable)return 3;}
        stop_event=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!stop_event)return 3;
        const auto delay=ohno::update_detail::integer(v,"stop_ms",1,30000);timer=std::thread([=]{WaitForSingleObject(stop_event,static_cast<DWORD>(delay));SetEvent(stop_event);});
        crash=static_cast<unsigned>(ohno::update_detail::integer(v,"crash",0,12));stop_at=static_cast<unsigned>(ohno::update_detail::integer(v,"stop_at",0,12));
        stop_after_poll=v.at("stop_after_poll").boolean;stop_after_rollback=v.at("stop_after_rollback").boolean;
        ohno::set_worker_test_hooks(worker_point,v.at("fail_drain").boolean);
        ohno::UpdateRuntimeOptions options;options.poll_ms=100;options.health_timeout_ms=400;options.restart_delay_ms=100;options.checkpoint=point;
        ohno::run_update_runtime(root,key,stop_event,[&]{return ohno::UpdateConnection{wide(text(v,"server")),text(v,"certificate"),key,text(v,"device_id"),text(v,"device_key")};},options);
        SetEvent(stop_event);timer.join();CloseHandle(stop_event);std::cout<<"stopped\n";return 0;
    }catch(...){if(stop_event)SetEvent(stop_event);if(timer.joinable())timer.join();if(stop_event)CloseHandle(stop_event);std::cerr<<"runtime rejected\n";return 1;}
}
