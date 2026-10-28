#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <wtsapi32.h>
#include <string>
#include <cwchar>
#include <vector>
#include <map>
#include <algorithm>
#include "monitor.hpp"
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wtsapi32.lib")
namespace {
struct handle { HANDLE h=INVALID_HANDLE_VALUE; ~handle(){if(h&&h!=INVALID_HANDLE_VALUE) CloseHandle(h);} };
struct algorithm { BCRYPT_ALG_HANDLE h=nullptr; ~algorithm(){if(h) BCryptCloseAlgorithmProvider(h,0);} };
struct hash_handle { BCRYPT_HASH_HANDLE h=nullptr; ~hash_handle(){if(h) BCryptDestroyHash(h);} };
struct cached { ULONGLONG size=0; FILETIME write{}; std::string hash; };
std::map<std::wstring,cached> cache;
std::string file_hash(const std::wstring& path) {
    handle file{CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,nullptr)};
    if(file.h==INVALID_HANDLE_VALUE)return {};
    BY_HANDLE_FILE_INFORMATION info{};if(!GetFileInformationByHandle(file.h,&info))return {};
    ULONGLONG size=(static_cast<ULONGLONG>(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
    // Avoid hashing enormous or special files on a classroom computer.
    if(size>512ULL*1024*1024)return {};
    auto prev=cache.find(path);
    if(prev!=cache.end()&&prev->second.size==size&&CompareFileTime(&prev->second.write,&info.ftLastWriteTime)==0)return prev->second.hash;
    algorithm alg;if(BCryptOpenAlgorithmProvider(&alg.h,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)return {};
    DWORD object_size=0,got=0;if(BCryptGetProperty(alg.h,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&object_size),sizeof(object_size),&got,0)<0)return {};
    std::vector<unsigned char> object(object_size);hash_handle hash;
    if(BCryptCreateHash(alg.h,&hash.h,object.data(),object_size,nullptr,0,0)<0)return {};
    std::vector<unsigned char> buf(65536);DWORD n=0;
    do {if(!ReadFile(file.h,buf.data(),static_cast<DWORD>(buf.size()),&n,nullptr))return {};if(n&&BCryptHashData(hash.h,buf.data(),n,0)<0)return {};}while(n);
    unsigned char digest[32]{};if(BCryptFinishHash(hash.h,digest,sizeof(digest),0)<0)return {};
    BY_HANDLE_FILE_INFORMATION after{};if(!GetFileInformationByHandle(file.h,&after)||after.nFileSizeHigh!=info.nFileSizeHigh||after.nFileSizeLow!=info.nFileSizeLow||CompareFileTime(&after.ftLastWriteTime,&info.ftLastWriteTime)!=0)return {};
    const char* hex="0123456789abcdef";std::string out;out.reserve(64);for(auto b:digest){out+=hex[b>>4];out+=hex[b&15];}
    if(cache.size()>2048)cache.clear();cache[path]={size,info.ftLastWriteTime,out};return out;
}
void show_notice(DWORD pid){
    DWORD session=0;if(!ProcessIdToSessionId(pid,&session)||session==0)return;
    wchar_t title[]=L"ohno 课堂助手";
    wchar_t message[]=L"此程序暂时被课堂规则限制，请联系教师。";
    DWORD result=0;WTSSendMessageW(WTS_CURRENT_SERVER_HANDLE,session,title,static_cast<DWORD>(wcslen(title)*sizeof(wchar_t)),message,static_cast<DWORD>(wcslen(message)*sizeof(wchar_t)),MB_OK|MB_ICONINFORMATION,15,&result,FALSE);
}
}
std::vector<std::string> stop_matching_processes(const std::vector<std::string>& blocked,const std::vector<std::string>& names,const std::vector<std::string>& allowed,DWORD only_pid){
    std::vector<std::string> stopped;if(blocked.empty()&&names.empty())return stopped;
    handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)};if(snapshot.h==INVALID_HANDLE_VALUE)return stopped;
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);
    if(!Process32FirstW(snapshot.h,&entry))return stopped;
    do {
        DWORD pid=entry.th32ProcessID;if((only_pid&&pid!=only_pid)||pid==0||pid==4||pid==GetCurrentProcessId())continue;
        bool named=false;for(const auto& n:names){std::wstring wide(n.begin(),n.end());if(_wcsicmp(entry.szExeFile,wide.c_str())==0){named=true;break;}}
        if(!named&&blocked.empty())continue;
        handle proc{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE,FALSE,pid)};if(!proc.h)continue;
        std::vector<wchar_t> path(32768);DWORD length=static_cast<DWORD>(path.size());
        if(!QueryFullProcessImageNameW(proc.h,0,path.data(),&length))continue;
        std::wstring image(path.data(),length);
        // Do not terminate operating-system processes even if configured by mistake.
        wchar_t root[MAX_PATH]{};UINT n=GetWindowsDirectoryW(root,MAX_PATH);
        if(n>0&&n<MAX_PATH&&image.size()>n&&_wcsnicmp(image.c_str(),root,n)==0&&(image[n]==L'\\'||image[n]==L'/'))continue;
        auto hash=file_hash(image);if(hash.empty()||std::find(allowed.begin(),allowed.end(),hash)!=allowed.end())continue;
        if(!named&&std::find(blocked.begin(),blocked.end(),hash)==blocked.end())continue;
        if(TerminateProcess(proc.h,ERROR_ACCESS_DISABLED_BY_POLICY)){stopped.push_back(hash);show_notice(pid);}
    }while(Process32NextW(snapshot.h,&entry));
    return stopped;
}
namespace {
bool has_download_zone(const std::wstring& path){
    auto stream=path+L":Zone.Identifier";
    handle f{CreateFileW(stream.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};
    if(f.h==INVALID_HANDLE_VALUE)return false;
    char buffer[8193]{};DWORD n=0;if(!ReadFile(f.h,buffer,8192,&n,nullptr))return false;
    std::string text(buffer,n);std::size_t pos=0;
    while(pos<text.size()){
        auto end=text.find_first_of("\r\n",pos);if(end==std::string::npos)end=text.size();
        auto line=text.substr(pos,end-pos);if(line=="ZoneId=3"||line=="ZoneId=4")return true;
        pos=end;while(pos<text.size()&&(text[pos]=='\r'||text[pos]=='\n'))++pos;
    }
    return false;
}
bool is_removable(const std::wstring& path){wchar_t volume[MAX_PATH]{};return GetVolumePathNameW(path.c_str(),volume,MAX_PATH)&&GetDriveTypeW(volume)==DRIVE_REMOVABLE;}
}
std::vector<UntrustedProgram> observe_untrusted_programs(){
    std::vector<UntrustedProgram> out;handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)};
    if(snapshot.h==INVALID_HANDLE_VALUE)return out;PROCESSENTRY32W e{};e.dwSize=sizeof(e);if(!Process32FirstW(snapshot.h,&e))return out;
    do{
        if(e.th32ProcessID==0||e.th32ProcessID==4||e.th32ProcessID==GetCurrentProcessId())continue;
        handle proc{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,e.th32ProcessID)};if(!proc.h)continue;
        std::vector<wchar_t> buffer(32768);DWORD n=static_cast<DWORD>(buffer.size());if(!QueryFullProcessImageNameW(proc.h,0,buffer.data(),&n))continue;
        std::wstring path(buffer.data(),n);if(!is_removable(path)&&!has_download_zone(path))continue;
        auto hash=file_hash(path);if(!hash.empty())out.push_back({path,hash});
    }while(Process32NextW(snapshot.h,&e));return out;
}
