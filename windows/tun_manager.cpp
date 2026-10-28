#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include "tun_manager.hpp"
#include "../src/tun_config.hpp"
TunManager::TunManager(HANDLE stop):stop_(stop){
    std::vector<wchar_t> path(32768);DWORD n=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if(n&&n<path.size()){std::wstring p(path.data(),n);auto slash=p.find_last_of(L"\\/");if(slash!=std::wstring::npos)dir_=p.substr(0,slash);}
}
TunManager::~TunManager(){stop_child();}
void TunManager::stop_child(){
    if(job_){TerminateJobObject(job_,0);CloseHandle(job_);job_=nullptr;}
    if(process_){WaitForSingleObject(process_,3000);CloseHandle(process_);process_=nullptr;}
}
bool TunManager::start(const std::string& config){
    if(dir_.empty())return false;auto temp=dir_+L"\\ohno-tun.json.tmp",target=dir_+L"\\ohno-tun.json",exe=dir_+L"\\ohno-tun.exe";
    HANDLE file=CreateFileW(temp.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);if(file==INVALID_HANDLE_VALUE)return false;
    DWORD written=0;BOOL ok=WriteFile(file,config.data(),static_cast<DWORD>(config.size()),&written,nullptr);if(ok)ok=FlushFileBuffers(file);CloseHandle(file);
    if(!ok||written!=config.size()||!MoveFileExW(temp.c_str(),target.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){DeleteFileW(temp.c_str());return false;}
    job_=CreateJobObjectW(nullptr,nullptr);if(!job_)return false;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!SetInformationJobObject(job_,JobObjectExtendedLimitInformation,&limits,sizeof(limits))){stop_child();return false;}
    std::wstring cmd=L"\""+exe+L"\" run -c \""+target+L"\"";STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
    if(!CreateProcessW(exe.c_str(),cmd.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW|CREATE_SUSPENDED,nullptr,dir_.c_str(),&si,&pi)){stop_child();return false;}
    if(!AssignProcessToJobObject(job_,pi.hProcess)){TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);stop_child();return false;}
    process_=pi.hProcess;ResumeThread(pi.hThread);CloseHandle(pi.hThread);
    HANDLE waits[2]{stop_,process_};DWORD status=WaitForMultipleObjects(2,waits,FALSE,2000);
    if(status!=WAIT_TIMEOUT){stop_child();return false;}
    config_=config;return true;
}
bool TunManager::ensure(const std::vector<std::string>& blocked,const std::vector<std::string>& allowed){
    std::string next;try{next=ohno::tun_config(blocked,allowed);}catch(...){return false;}
    if(process_&&WaitForSingleObject(process_,0)==WAIT_TIMEOUT&&next==config_)return true;
    ULONGLONG now=GetTickCount64();if(last_attempt_&&now-last_attempt_<10000)return false;
    stop_child();last_attempt_=now;return start(next);
}
