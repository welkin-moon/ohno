#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>
#include "installed_payload.hpp"
#include "trusted_directory.hpp"
namespace {
struct Handle{HANDLE h=INVALID_HANDLE_VALUE;explicit Handle(HANDLE v):h(v){}~Handle(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}};
void require(bool value){if(!value)throw std::runtime_error("installed payload access failed");}
std::wstring wide(const std::string& s){return {s.begin(),s.end()};}
std::string bounded_file(const std::wstring& path,std::size_t max,bool selector=false){
    Handle file(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|(selector?FILE_SHARE_DELETE:0),nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};
    require(file.h!=INVALID_HANDLE_VALUE&&GetFileInformationByHandle(file.h,&info)&&info.nNumberOfLinks==1&&!(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))&&GetFileSizeEx(file.h,&size)&&size.QuadPart>0&&static_cast<std::uint64_t>(size.QuadPart)<=max);
    std::string data(static_cast<std::size_t>(size.QuadPart),'\0');DWORD read=0;require(ReadFile(file.h,data.data(),static_cast<DWORD>(data.size()),&read,nullptr)&&read==data.size());return data;
}
bool remove_file(const std::wstring& path){
    const auto attributes=GetFileAttributesW(path.c_str());if(attributes==INVALID_FILE_ATTRIBUTES)return GetLastError()==ERROR_FILE_NOT_FOUND;
    if(attributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))return false;
    {Handle file(CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));BY_HANDLE_FILE_INFORMATION info{};
        if(file.h==INVALID_HANDLE_VALUE||!GetFileInformationByHandle(file.h,&info)||info.nNumberOfLinks!=1)return false;}
    return DeleteFileW(path.c_str())!=FALSE;
}
bool owned_name(const std::wstring& name){
    const auto ascii=std::string(name.begin(),name.end());
    if(name.size()==71&&name.compare(0,7,L".stage-")==0)return ohno::update_detail::lower_hex(ascii.substr(7),64);
    const auto dash=ascii.find('-');if(dash==std::string::npos||dash>16||!dash||!ohno::update_detail::lower_hex(ascii.substr(dash+1),64))return false;
    const auto seq=ascii.substr(0,dash);if(seq.size()>1&&seq.front()=='0')return false;for(char c:seq)if(c<'0'||c>'9')return false;return true;
}
}
namespace ohno {
std::wstring installed_request_helper(const std::wstring& root,const std::string& key){
    TrustedDirectory trusted(root);const auto journal=parse_update_journal(bounded_file(root+L"\\update-state.json",4096,true));
    // A still-probationary GUI must not replace a committed one. The journal's
    // immutable revision identity keeps a concurrent selector update harmless.
    const auto& revision=journal.last_good;verify_staged_payload(root,revision,key);
    return root+L"\\versions\\"+std::to_wstring(revision.sequence)+L"-"+wide(revision.sha256)+L"\\ohno-request.exe";
}
bool remove_installed_payloads(const std::wstring& root){
    try{
        TrustedDirectory trusted(root);bool ok=true;const auto versions=root+L"\\versions";
        if(GetFileAttributesW(versions.c_str())!=INVALID_FILE_ATTRIBUTES){
            {
                TrustedDirectory parent(versions);WIN32_FIND_DATAW item{};HANDLE search=FindFirstFileW((versions+L"\\*").c_str(),&item);
                require(search!=INVALID_HANDLE_VALUE);
                do {
                    const std::wstring name=item.cFileName;if(name==L"."||name==L"..")continue;
                    if(!owned_name(name)||!(item.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||(item.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)){ok=false;continue;}
                    const auto path=versions+L"\\"+name;
                    try{
                        {TrustedDirectory child(path);
                            if(bounded_file(path+L"\\staging.owner",64)!="ohno-stage-v1\n"){ok=false;continue;}
                            for(const char* file:update_payload_names)if(!remove_file(path+L"\\"+wide(file)))ok=false;
                            for(const wchar_t* file:{L"payload.ohno",L"release.json",L"staging.owner",L"ohno-tun.json",L"ohno-tun.json.tmp"})if(!remove_file(path+L"\\"+file))ok=false;
                        }
                        if(!RemoveDirectoryW(path.c_str()))ok=false;
                    }catch(...){ok=false;}
                }while(FindNextFileW(search,&item));
                const DWORD error=GetLastError();FindClose(search);if(error!=ERROR_NO_MORE_FILES)ok=false;
            }
            if(!RemoveDirectoryW(versions.c_str()))ok=false;
        }else if(GetLastError()!=ERROR_FILE_NOT_FOUND)ok=false;
        WIN32_FIND_DATAW download{};HANDLE downloads=FindFirstFileW((root+L"\\download-*.tmp").c_str(),&download);
        if(downloads!=INVALID_HANDLE_VALUE){
            do {const std::wstring name=download.cFileName;const std::string ascii(name.begin(),name.end());
                if(name.size()==77&&name.compare(0,9,L"download-")==0&&name.compare(73,4,L".tmp")==0&&update_detail::lower_hex(ascii.substr(9,64),64)){
                    if(!remove_file(root+L"\\"+name))ok=false;
                }
            }while(FindNextFileW(downloads,&download));const DWORD error=GetLastError();FindClose(downloads);if(error!=ERROR_NO_MORE_FILES)ok=false;
        }else if(GetLastError()!=ERROR_FILE_NOT_FOUND)ok=false;
        // Service is stopped before this function. Do not follow arbitrary link
        // targets or clean unrelated files even in administrator recovery mode.
        for(const wchar_t* name:{L"update-state.json",L"update-state.next",L"update.lock"})if(!remove_file(root+L"\\"+name))ok=false;
        return ok;
    }catch(...){return false;}
}
}
