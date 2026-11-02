#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fstream>
#include <filesystem>
#include <iostream>
#include "../windows/installed_payload.hpp"
int wmain(int argc,wchar_t** argv){
    try{
        if(argc<3)return 2;std::wstring root=argv[1],mode=argv[2];
        if(mode==L"init"){
            if(argc!=4)return 2;std::ifstream f(std::filesystem::path(argv[3]),std::ios::binary);std::string bytes{std::istreambuf_iterator<char>(f),{}};
            ohno::WindowsUpdateJournal storage(root);auto initial=ohno::stage_initial_payload(storage,bytes);
            if(storage.initialize(ohno::initial_update_journal(initial))!=ohno::JournalWrite::Durable)return 1;
            // A read-only launcher must work while the host owns writer lock.
            auto path=ohno::installed_request_helper(root,{});if(path.find(L"\\versions\\0-")==std::wstring::npos)return 1;return 0;
        }
        if(mode==L"view"){ohno::installed_request_helper(root,{});return 0;}
        if(mode==L"remove")return ohno::remove_installed_payloads(root)?0:1;
        return 2;
    }catch(...){return 1;}
}
