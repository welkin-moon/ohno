#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cwchar>
#include <iostream>
#include "../windows/update_journal.hpp"
unsigned fault=0;
void crash(unsigned point){if(point==fault)ExitProcess(100+point);}
int wmain(int argc,wchar_t** argv){
    if(argc<3||argc>4)return 2;
    try {
        ohno::WindowsUpdateJournal disk(argv[1]);
        const std::wstring action=argv[2];
        if(argc==4){fault=static_cast<unsigned>(std::wcstoul(argv[3],nullptr,10));ohno::WindowsUpdateJournal::set_test_fault_hook(crash);}
        if(action==L"init"){
            auto initial=ohno::initial_update_journal({0,"0.1.0-alpha.6",std::string(64,'a')});
            return disk.initialize(initial)==ohno::JournalWrite::Durable?0:1;
        }
        auto state=ohno::parse_update_journal(disk.read());
        if(action==L"read"){std::cout<<ohno::serialize_update_journal(state);return 0;}
        if(action==L"hold"){std::cout<<"locked"<<std::endl;std::string line;std::getline(std::cin,line);return 0;}
        ohno::UpdateJournal next;
        if(action==L"prepare")next=ohno::prepare_update(state,{7,"0.2.0",std::string(64,'b')},std::string(64,'c'));
        else if(action==L"activate")next=ohno::activate_update(state,std::string(64,'c'));
        else if(action==L"commit")next=ohno::commit_update_health(state,{std::string(64,'c'),{7,"0.2.0",std::string(64,'b')},1});
        else if(action==L"recover"||action==L"rollback")next=ohno::recover_update(state);
        else return 2;
        if(ohno::serialize_update_journal(state)!=ohno::serialize_update_journal(next))ohno::persist_update_transition(disk,state,next);
        return 0;
    }catch(const std::exception&){std::cerr<<"journal rejected; no runnable state selected\n";return 1;}
}
