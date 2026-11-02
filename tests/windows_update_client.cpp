#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <thread>
#include "../windows/update_client.hpp"

namespace {
unsigned fault=0;
void crash(unsigned point){if(point==fault)ExitProcess(100+point);}
std::wstring wide(const std::string& text){
    const int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);
    if(count<=0)throw std::runtime_error("fixture encoding");std::wstring result(static_cast<std::size_t>(count),L'\0');
    if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),result.data(),count))throw std::runtime_error("fixture encoding");return result;
}
std::string read(const std::wstring& path){std::ifstream in(std::filesystem::path(path),std::ios::binary);if(!in)throw std::runtime_error("fixture file");return {std::istreambuf_iterator<char>(in),{}};}
}
int main(){
    HANDLE stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);std::thread timer;int result=1;
    try {
        std::string input(std::istreambuf_iterator<char>(std::cin),{});auto config=ohno_json::parse(input);
        auto text=[&](const char* name){return ohno::update_detail::text(config,name);};
        auto number=[&](const char* name,std::uint64_t fallback){return config.fields.count(name)?ohno::update_detail::integer(config,name,0,ohno::max_update_sequence):fallback;};
        const auto mode=text("mode");
        ohno::WindowsUpdateJournal disk(wide(text("root")));
        fault=static_cast<unsigned>(number("fault",0));ohno::set_payload_test_fault_hook(crash);
        const auto cancel=number("cancel_ms",0);
        if(config.fields.count("cancel_before")&&config.at("cancel_before").boolean)SetEvent(stop);
        if(cancel)timer=std::thread([stop,cancel]{Sleep(static_cast<DWORD>(cancel));SetEvent(stop);});
        if(mode=="initial"){
            const auto package=read(wide(text("package")));const auto revision=ohno::stage_initial_payload(disk,package,stop);
            if(disk.initialize(ohno::initial_update_journal(revision))!=ohno::JournalWrite::Durable)throw std::runtime_error("fixture init");
            ohno::verify_staged_payload(disk,revision,"",stop);std::cout<<disk.read();result=0;
        }else{
            if(config.fields.count("initialize")&&config.at("initialize").boolean){
                auto initial=ohno::initial_update_journal({number("floor",0),"0.1.0-alpha.6",std::string(64,'a')});
                if(disk.initialize(initial)!=ohno::JournalWrite::Durable)throw std::runtime_error("fixture init");
            }
            const auto current=ohno::parse_update_journal(disk.read());
            if(mode=="fetch"){
                ohno::UpdateConnection connection{wide(text("server")),text("certificate"),text("public_key"),text("device_id"),text("device_key")};
                const auto staged=ohno::fetch_staged_update(disk,connection,current,stop);
                if(staged){
                    ohno::verify_staged_payload(disk,staged->revision,connection.release_public_key,stop);
                    const bool authorized=ohno::authorize_staged_update(connection,*staged,stop);
                    std::cout<<"{\"staged\":true,\"authorized\":"<<(authorized?"true":"false")<<",\"sequence\":"<<staged->revision.sequence<<"}";
                }else std::cout<<"{\"staged\":false}";
                SecureZeroMemory(connection.device_key.data(),connection.device_key.size());result=0;
            }else{
                const auto document=text("document");const auto manifest=ohno::parse_update_manifest(document);
                ohno::UpdateRevision revision{manifest.sequence,manifest.version,manifest.sha256};
                if(mode=="stage")revision=ohno::stage_update_payload(disk,document,text("public_key"),wide(text("package")),current.high_water,number("now",manifest.issued_at),stop);
                else if(mode!="verify")throw std::runtime_error("fixture mode");
                ohno::verify_staged_payload(disk,revision,text("public_key"),stop);std::cout<<disk.read();result=0;
            }
        }
    }catch(const std::exception&){std::cerr<<"update fixture rejected; no candidate executed\n";}
    if(timer.joinable())timer.join();if(stop)CloseHandle(stop);return result;
}
