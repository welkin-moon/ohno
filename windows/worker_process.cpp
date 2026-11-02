#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>
#include <utility>
#include "worker_process.hpp"
namespace {
void require(bool ok){if(!ok)throw std::runtime_error("worker creation or health failed");}
struct Handle{HANDLE h=nullptr;~Handle(){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);}Handle()=default;Handle(const Handle&)=delete;};
struct Attributes {
    std::vector<unsigned char> bytes;LPPROC_THREAD_ATTRIBUTE_LIST list=nullptr;
    Attributes(){SIZE_T size=0;InitializeProcThreadAttributeList(nullptr,1,0,&size);require(size>0);bytes.resize(size);
        list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(bytes.data());require(InitializeProcThreadAttributeList(list,1,0,&size)!=FALSE);}
    ~Attributes(){if(list)DeleteProcThreadAttributeList(list);}
};
std::wstring wide(const std::string& ascii){return {ascii.begin(),ascii.end()};}
void uncanceled(HANDLE stop){require(!stop||WaitForSingleObject(stop,0)==WAIT_TIMEOUT);}
}
namespace ohno {
struct WorkerProcess::Impl {
    Handle job,process,stop,read;UpdateRevision revision;std::string transaction;
    void end() noexcept {
        if(stop.h)SetEvent(stop.h);
        if(process.h&&WaitForSingleObject(process.h,8000)==WAIT_TIMEOUT&&job.h)TerminateJobObject(job.h,1);
        if(process.h)WaitForSingleObject(process.h,3000);
        if(job.h){CloseHandle(job.h);job.h=nullptr;}
    }
    ~Impl(){end();}
};
WorkerProcess::WorkerProcess(WindowsUpdateJournal& storage,const UpdateRevision& revision,
    const std::string& key,const std::string& transaction,HANDLE host_stop,ULONGLONG not_after):impl(std::make_unique<Impl>()) {
    require(update_detail::lower_hex(transaction,64));uncanceled(host_stop);
    // Revalidate all extracted bytes immediately before CreateProcess. The
    // installation ACL and pinned ancestor directories are the trust boundary.
    verify_staged_payload(storage,revision,key,host_stop);
    impl->revision=revision;impl->transaction=transaction;
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
    impl->stop.h=CreateEventW(&sa,TRUE,FALSE,nullptr);require(impl->stop.h!=nullptr);
    Handle writer;require(CreatePipe(&impl->read.h,&writer.h,&sa,1024)!=FALSE);
    require(SetHandleInformation(impl->read.h,HANDLE_FLAG_INHERIT,0)!=FALSE);
    impl->job.h=CreateJobObjectW(nullptr,nullptr);require(impl->job.h!=nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    require(SetInformationJobObject(impl->job.h,JobObjectExtendedLimitInformation,&limits,sizeof(limits))!=FALSE);
    const auto directory=payload_directory(storage,revision),exe=directory+L"\\ohno-worker.exe";
    std::wstring command=L"\""+exe+L"\" --worker "+std::to_wstring(reinterpret_cast<std::uintptr_t>(impl->stop.h))+L" "+
        std::to_wstring(reinterpret_cast<std::uintptr_t>(writer.h))+L" "+wide(transaction)+L" "+
        std::to_wstring(revision.sequence)+L" "+wide(revision.version)+L" "+wide(revision.sha256);
    Attributes attributes;HANDLE inherited[2]{impl->stop.h,writer.h};
    require(UpdateProcThreadAttribute(attributes.list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr)!=FALSE);
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=attributes.list;PROCESS_INFORMATION child{};
    uncanceled(host_stop);require(!not_after||GetTickCount64()<not_after);
    require(CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,TRUE,
        CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,directory.c_str(),&startup.StartupInfo,&child)!=FALSE);
    impl->process.h=child.hProcess;Handle thread;thread.h=child.hThread;
    if(!AssignProcessToJobObject(impl->job.h,impl->process.h)){
        TerminateProcess(impl->process.h,1);throw std::runtime_error("worker job assignment failed");
    }
    uncanceled(host_stop);require(!not_after||GetTickCount64()<not_after);require(ResumeThread(thread.h)!=DWORD(-1));
}
WorkerProcess::~WorkerProcess()=default;
void WorkerProcess::stop() noexcept {impl->end();}
bool WorkerProcess::running() const {return impl->process.h&&WaitForSingleObject(impl->process.h,0)==WAIT_TIMEOUT;}
bool WorkerProcess::healthy(HANDLE host_stop,DWORD timeout,UpdateHealth& proof) {
    const auto start=GetTickCount64();std::string document;document.reserve(512);
    while(GetTickCount64()-start<timeout){
        if((host_stop&&WaitForSingleObject(host_stop,0)!=WAIT_TIMEOUT)||!running())return false;
        DWORD available=0;if(!PeekNamedPipe(impl->read.h,nullptr,0,nullptr,&available,nullptr))return false;
        if(available){
            if(available>512-document.size())return false;
            char bytes[512];DWORD read=0;if(!ReadFile(impl->read.h,bytes,available,&read,nullptr)||read!=available)return false;
            document.append(bytes,read);
            if(document.find('\n')!=std::string::npos){
                try{proof=parse_update_health(document);return proof.transaction==impl->transaction&&proof.revision==impl->revision&&running();}catch(...){return false;}
            }
        }
        if(host_stop){if(WaitForSingleObject(host_stop,20)!=WAIT_TIMEOUT)return false;}else Sleep(20);
    }
    return false;
}
}
