#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <vector>
#include "update_payload.hpp"
#include "update_verify.hpp"
#pragma comment(lib,"bcrypt.lib")
namespace {
#ifdef OHNO_UPDATE_IO_TESTING
void(*payload_fault_hook)(unsigned)=nullptr;
void checkpoint(unsigned point){if(payload_fault_hook)payload_fault_hook(point);}
#else
void checkpoint(unsigned){}
#endif
void require(bool ok){if(!ok)throw std::runtime_error("update payload verification or staging failed");}
void canceled(HANDLE stop){if(stop&&WaitForSingleObject(stop,0)==WAIT_OBJECT_0)throw std::runtime_error("update canceled");}
struct Handle{HANDLE h=INVALID_HANDLE_VALUE;explicit Handle(HANDLE value=INVALID_HANDLE_VALUE):h(value){}~Handle(){if(h!=INVALID_HANDLE_VALUE&&h)CloseHandle(h);}Handle(const Handle&)=delete;};
void regular(HANDLE file){BY_HANDLE_FILE_INFORMATION info{};require(file!=INVALID_HANDLE_VALUE&&GetFileInformationByHandle(file,&info)&&info.nNumberOfLinks==1&&!(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)));}
struct Mapped {
    Handle file,mapping;const char* bytes=nullptr;std::size_t size=0;
    explicit Mapped(const std::wstring& path,std::uint64_t maximum=ohno::max_update_package_size):
        file(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr)){
        regular(file.h);LARGE_INTEGER length{};require(GetFileSizeEx(file.h,&length)&&length.QuadPart>0&&static_cast<std::uint64_t>(length.QuadPart)<=maximum);
        size=static_cast<std::size_t>(length.QuadPart);mapping.h=CreateFileMappingW(file.h,nullptr,PAGE_READONLY,0,0,nullptr);require(mapping.h!=nullptr);
        bytes=static_cast<const char*>(MapViewOfFile(mapping.h,FILE_MAP_READ,0,0,0));require(bytes!=nullptr);
    }
    ~Mapped(){if(bytes)UnmapViewOfFile(bytes);}
    std::string_view view() const{return {bytes,size};}
};
struct Algorithm{BCRYPT_ALG_HANDLE h=nullptr;~Algorithm(){if(h)BCryptCloseAlgorithmProvider(h,0);}};
struct Hash{BCRYPT_HASH_HANDLE h=nullptr;~Hash(){if(h)BCryptDestroyHash(h);}};
std::string digest(std::string_view bytes,HANDLE stop){
    Algorithm algorithm;require(BCryptOpenAlgorithmProvider(&algorithm.h,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0);
    DWORD object_size=0,got=0;require(BCryptGetProperty(algorithm.h,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&object_size),sizeof(object_size),&got,0)>=0&&got==sizeof(object_size)&&object_size<=65536);
    std::vector<unsigned char> object(object_size);Hash hash;require(BCryptCreateHash(algorithm.h,&hash.h,object.data(),object_size,nullptr,0,0)>=0);
    for(std::size_t offset=0;offset<bytes.size();){canceled(stop);const auto count=static_cast<ULONG>((std::min)(bytes.size()-offset,std::size_t(65536)));
        require(BCryptHashData(hash.h,reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data()+offset)),count,0)>=0);offset+=count;}
    std::array<unsigned char,32> result{};require(BCryptFinishHash(hash.h,result.data(),static_cast<ULONG>(result.size()),0)>=0);
    std::string output;constexpr char hex[]="0123456789abcdef";for(auto ch:result){output+=hex[ch>>4];output+=hex[ch&15];}return output;
}
void write_new(const std::wstring& path,std::string_view bytes,HANDLE stop){
    Handle file(CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr));regular(file.h);
    for(std::size_t offset=0;offset<bytes.size();){canceled(stop);const auto count=static_cast<DWORD>((std::min)(bytes.size()-offset,std::size_t(65536)));DWORD wrote=0;
        require(WriteFile(file.h,bytes.data()+offset,count,&wrote,nullptr)&&wrote==count);offset+=count;}
    require(FlushFileBuffers(file.h)!=FALSE);
}
std::wstring wide(const std::string& ascii){return {ascii.begin(),ascii.end()};}
struct Directory {
    Handle handle;
    explicit Directory(const std::wstring& path):handle(CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr)){
        BY_HANDLE_FILE_INFORMATION info{};require(handle.h!=INVALID_HANDLE_VALUE&&GetFileInformationByHandle(handle.h,&info)&&
            (info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&!(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));
    }
};
std::wstring versions(const ohno::WindowsUpdateJournal& storage){return storage.directory_path()+L"\\versions";}
void remove_owned_stage(const std::wstring& path) noexcept {
    // Only our freshly created directory and exact fixed filenames; never
    // recurse into or remove unknown content/reparse target directories.
    const DWORD attributes=GetFileAttributesW(path.c_str());
    if(attributes==INVALID_FILE_ATTRIBUTES||!(attributes&FILE_ATTRIBUTE_DIRECTORY)||(attributes&FILE_ATTRIBUTE_REPARSE_POINT))return;
    for(const char* name:ohno::update_payload_names)DeleteFileW((path+L"\\"+wide(name)).c_str());
    DeleteFileW((path+L"\\payload.ohno").c_str());DeleteFileW((path+L"\\release.json").c_str());DeleteFileW((path+L"\\staging.owner").c_str());RemoveDirectoryW(path.c_str());
}
void cleanup_owned_stages(const std::wstring& root){
    WIN32_FIND_DATAW found{};HANDLE search=FindFirstFileW((root+L"\\.stage-*").c_str(),&found);
    if(search==INVALID_HANDLE_VALUE){require(GetLastError()==ERROR_FILE_NOT_FOUND);return;}
    do{
        const std::wstring name=found.cFileName;
        if(name.size()!=71||name.compare(0,7,L".stage-")!=0||!(found.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||
            (found.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))continue;
        bool valid=true;for(std::size_t i=7;i<name.size();++i)if(!((name[i]>=L'0'&&name[i]<=L'9')||(name[i]>=L'a'&&name[i]<=L'f')))valid=false;
        if(!valid)continue;
        const auto path=root+L"\\"+name;
        bool ours=false;
        try {Mapped owner(path+L"\\staging.owner",64);ours=owner.view()=="ohno-stage-v1\n";}catch(...){}
        if(ours)remove_owned_stage(path);
        else RemoveDirectoryW(path.c_str()); // only succeeds for empty directory
    }while(FindNextFileW(search,&found));
    const DWORD error=GetLastError();FindClose(search);require(error==ERROR_NO_MORE_FILES);
}
void stage(ohno::WindowsUpdateJournal& storage,std::string_view package,const ohno::UpdatePackage& parsed,
           const ohno::UpdateRevision& revision,const std::string& offer,const std::string& key,HANDLE stop){
    const auto root=versions(storage);if(!CreateDirectoryW(root.c_str(),nullptr))require(GetLastError()==ERROR_ALREADY_EXISTS);
    Directory parent(root);cleanup_owned_stages(root);const auto final=ohno::payload_directory(storage,revision);
    if(GetFileAttributesW(final.c_str())!=INVALID_FILE_ATTRIBUTES){ohno::verify_staged_payload(storage,revision,key,stop);return;}
    require(GetLastError()==ERROR_FILE_NOT_FOUND);
    std::array<unsigned char,32> random{};require(BCryptGenRandom(nullptr,random.data(),static_cast<ULONG>(random.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0);
    std::string suffix;constexpr char hex[]="0123456789abcdef";for(auto ch:random){suffix+=hex[ch>>4];suffix+=hex[ch&15];}
    const auto temporary=root+L"\\.stage-"+wide(suffix);require(CreateDirectoryW(temporary.c_str(),nullptr)!=FALSE);
    bool moved=false;
    try {
        {
            Directory pinned(temporary);
            write_new(temporary+L"\\staging.owner","ohno-stage-v1\n",stop);
            for(std::size_t i=0;i<parsed.files.size();++i){const auto& file=parsed.files[i];write_new(temporary+L"\\"+wide(ohno::update_payload_names[i]),package.substr(file.offset,file.size),stop);checkpoint(static_cast<unsigned>(i)+1);}
            write_new(temporary+L"\\payload.ohno",package,stop);checkpoint(7);
            write_new(temporary+L"\\release.json",offer.empty()?std::string_view("{\"baseline\":true}\n"):std::string_view(offer),stop);checkpoint(8);
        }
        canceled(stop);checkpoint(9);require(MoveFileExW(temporary.c_str(),final.c_str(),MOVEFILE_WRITE_THROUGH)!=FALSE);moved=true;checkpoint(10);
        ohno::verify_staged_payload(storage,revision,key,stop);
    } catch(...) {if(!moved)remove_owned_stage(temporary);throw;}
}
}
namespace ohno {
#ifdef OHNO_UPDATE_IO_TESTING
void set_payload_test_fault_hook(void(*hook)(unsigned)){payload_fault_hook=hook;}
#endif
std::wstring payload_directory(const WindowsUpdateJournal& storage,const UpdateRevision& revision){
    transaction_detail::revision(revision);
    return versions(storage)+L"\\"+std::to_wstring(revision.sequence)+L"-"+wide(revision.sha256);
}
UpdateRevision stage_update_payload(WindowsUpdateJournal& storage,const std::string& offer,const std::string& pinned_key,
    const std::wstring& package_file,std::uint64_t high_water,std::uint64_t now,HANDLE stop){
    canceled(stop);const auto manifest=verify_update_offer(offer,pinned_key,high_water,updater_protocol_version,now);
    Mapped package(package_file);require(package.size==manifest.size&&digest(package.view(),stop)==manifest.sha256);
    const auto parsed=parse_update_package(package.view());require(parsed.version==manifest.version);
    UpdateRevision revision{manifest.sequence,manifest.version,manifest.sha256};
    stage(storage,package.view(),parsed,revision,offer,pinned_key,stop);return revision;
}
UpdateRevision stage_initial_payload(WindowsUpdateJournal& storage,std::string_view package,HANDLE stop){
    canceled(stop);const auto parsed=parse_update_package(package);
    UpdateRevision revision{0,parsed.version,digest(package,stop)};
    stage(storage,package,parsed,revision,{}, {},stop);return revision;
}
void verify_staged_payload(WindowsUpdateJournal& storage,const UpdateRevision& revision,const std::string& pinned_key,HANDLE stop){
    canceled(stop);const auto folder=payload_directory(storage,revision);Directory parent(versions(storage)),pinned(folder);
    Mapped package(folder+L"\\payload.ohno");require(digest(package.view(),stop)==revision.sha256);
    const auto parsed=parse_update_package(package.view());require(parsed.version==revision.version);
    Mapped record(folder+L"\\release.json",4096);
    if(revision.sequence){
        const auto manifest=verify_update_signature(std::string(record.bytes,record.size),pinned_key);
        require(manifest.sequence==revision.sequence&&manifest.sha256==revision.sha256&&manifest.version==revision.version&&
            manifest.size==package.size&&manifest.min_updater<=updater_protocol_version);
    }else require(record.view()=="{\"baseline\":true}\n");
    for(std::size_t i=0;i<parsed.files.size();++i){
        Mapped file(folder+L"\\"+wide(update_payload_names[i]));const auto& range=parsed.files[i];require(file.size==range.size);
        for(std::size_t offset=0;offset<file.size;){canceled(stop);const auto count=(std::min)(file.size-offset,std::size_t(65536));
            require(std::memcmp(file.bytes+offset,package.bytes+range.offset+offset,count)==0);offset+=count;}
    }
}
}
