#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <algorithm>
#include <cwchar>
#include <vector>
#include "update_journal.hpp"

namespace {
struct Handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h=INVALID_HANDLE_VALUE):value(h){}
    ~Handle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
    Handle(const Handle&)=delete;
    Handle& operator=(const Handle&)=delete;
    Handle(Handle&& other) noexcept:value(other.value){other.value=INVALID_HANDLE_VALUE;}
};
void require(bool ok){if(!ok)throw std::runtime_error("update journal filesystem operation failed");}
void regular_file(HANDLE h){
    BY_HANDLE_FILE_INFORMATION info{};
    require(h!=INVALID_HANDLE_VALUE && GetFileInformationByHandle(h,&info) &&
        !(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) && info.nNumberOfLinks==1);
}
Handle open_record(const std::wstring& path,DWORD access){
    Handle file(CreateFileW(path.c_str(),access,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr));
    regular_file(file.value);return file;
}
#ifdef OHNO_UPDATE_IO_TESTING
ohno::WindowsUpdateJournal::FaultHook fault_hook=nullptr;
void checkpoint(unsigned point){if(fault_hook)fault_hook(point);}
#else
void checkpoint(unsigned){}
#endif
}
namespace ohno {
struct WindowsUpdateJournal::Impl {
    std::wstring directory,record,pending;
    std::vector<Handle> ancestors;
    Handle lock;
    bool uncertain=false;
    explicit Impl(const std::wstring& root) {
        // Deliberately no UNC/device namespace/network filesystem support.
        require(root.size()>3 && root.size()<240 &&
            ((root[0]>=L'A'&&root[0]<=L'Z')||(root[0]>=L'a'&&root[0]<=L'z')) && root[1]==L':' && root[2]==L'\\' &&
            root.find(L'/',0)==std::wstring::npos && root.find(L':',2)==std::wstring::npos);
        wchar_t full[32768]{};const auto length=GetFullPathNameW(root.c_str(),32768,full,nullptr);
        require(length>0&&length<32768);directory.assign(full,length);
        while(directory.size()>3&&directory.back()==L'\\')directory.pop_back();
        require(directory==root); // no relative/dot/trailing aliases
        wchar_t filesystem[32]{};
        require(GetVolumeInformationW(directory.substr(0,3).c_str(),nullptr,0,nullptr,nullptr,nullptr,filesystem,32)!=FALSE &&
            _wcsicmp(filesystem,L"NTFS")==0);
        // Pin every ancestor against rename/delete during the transaction and
        // reject junction/symlink traversal rather than following it.
        for(std::size_t end=3;;) {
            const auto path=directory.substr(0,end);
            Handle handle(CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
            BY_HANDLE_FILE_INFORMATION info{};
            require(handle.value!=INVALID_HANDLE_VALUE&&GetFileInformationByHandle(handle.value,&info) &&
                (info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) && !(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));
            ancestors.push_back(std::move(handle));
            if(end==directory.size())break;
            const auto next=directory.find(L'\\',end+1);end=next==std::wstring::npos?directory.size():next;
        }
        record=directory+L"\\update-state.json";pending=directory+L"\\update-state.next";
        lock.value=CreateFileW((directory+L"\\update.lock").c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_ALWAYS,
            FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        regular_file(lock.value);
    }
    std::string read() {
        require(!uncertain);
        auto file=open_record(record,GENERIC_READ);
        LARGE_INTEGER size{};require(GetFileSizeEx(file.value,&size)&&size.QuadPart>0&&size.QuadPart<=4096);
        std::string result(static_cast<std::size_t>(size.QuadPart),'\0');DWORD got=0;
        require(ReadFile(file.value,result.data(),static_cast<DWORD>(result.size()),&got,nullptr)&&got==result.size());
        // Corruption is a hard failure, never a fallback to an older replay floor.
        parse_update_journal(result);return result;
    }
    JournalWrite write(const std::string& document,bool initial) {
        require(!uncertain);parse_update_journal(document);
        // A stale, private pending file can only predate the atomic selector
        // change. Remove ONLY this fixed regular file; never follow a link.
        const DWORD attributes=GetFileAttributesW(pending.c_str());
        if(attributes!=INVALID_FILE_ATTRIBUTES) {
            {auto stale=open_record(pending,GENERIC_READ);}
            require(DeleteFileW(pending.c_str())!=FALSE);
        } else require(GetLastError()==ERROR_FILE_NOT_FOUND);
        checkpoint(1);
        {
            Handle file(CreateFileW(pending.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr));
            if(file.value==INVALID_HANDLE_VALUE)return JournalWrite::NotWritten;
            regular_file(file.value);
            DWORD wrote=0;const DWORD half=static_cast<DWORD>(document.size()/2);
            if(!WriteFile(file.value,document.data(),half,&wrote,nullptr)||wrote!=half)return JournalWrite::NotWritten;
            checkpoint(2);
            const DWORD remaining=static_cast<DWORD>(document.size())-half;
            if(!WriteFile(file.value,document.data()+half,remaining,&wrote,nullptr)||wrote!=remaining)return JournalWrite::NotWritten;
            checkpoint(3);
            if(!FlushFileBuffers(file.value))return JournalWrite::NotWritten;
            checkpoint(4);
        }
        checkpoint(5);
        // Same-directory rename only: no COPY_ALLOWED fallback, no deferred
        // reboot action. NTFS atomically selects the old or complete new file.
        // https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw
        if(!MoveFileExW(pending.c_str(),record.c_str(),MOVEFILE_WRITE_THROUGH|(initial?0:MOVEFILE_REPLACE_EXISTING))) {
            // Do not guess whether a lower-level storage fault committed it.
            uncertain=true;return JournalWrite::Uncertain;
        }
        checkpoint(6);
        try {
            auto final=open_record(record,GENERIC_READ|GENERIC_WRITE);
            if(!FlushFileBuffers(final.value)){uncertain=true;return JournalWrite::Uncertain;}
        } catch(...) {uncertain=true;return JournalWrite::Uncertain;}
        checkpoint(7);
        return JournalWrite::Durable;
    }
};
WindowsUpdateJournal::WindowsUpdateJournal(const std::wstring& directory):impl(std::make_unique<Impl>(directory)){}
WindowsUpdateJournal::~WindowsUpdateJournal()=default;
std::string WindowsUpdateJournal::read(){return impl->read();}
JournalWrite WindowsUpdateJournal::replace(const std::string& document){
    impl->read(); // missing/corrupt state can never be silently reconstructed
    return impl->write(document,false);
}
JournalWrite WindowsUpdateJournal::initialize(const UpdateJournal& initial){
    transaction_detail::validate(initial);
    require(initial.generation==1&&initial.phase==UpdatePhase::Stable&&initial.high_water==initial.active.sequence);
    require(GetFileAttributesW(impl->record.c_str())==INVALID_FILE_ATTRIBUTES&&GetLastError()==ERROR_FILE_NOT_FOUND);
    return impl->write(serialize_update_journal(initial),true);
}
#ifdef OHNO_UPDATE_IO_TESTING
void WindowsUpdateJournal::set_test_fault_hook(FaultHook hook){fault_hook=hook;}
#endif
}
