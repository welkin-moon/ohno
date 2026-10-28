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
std::vector<std::string> stop_matching_processes(const std::vector<std::string>& blocked){
    std::vector<std::string> stopped;if(blocked.empty())return stopped;
    handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)};if(snapshot.h==INVALID_HANDLE_VALUE)return stopped;
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);
    if(!Process32FirstW(snapshot.h,&entry))return stopped;
    do {
        DWORD pid=entry.th32ProcessID;if(pid==0||pid==4||pid==GetCurrentProcessId())continue;
        handle proc{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE,FALSE,pid)};if(!proc.h)continue;
        std::vector<wchar_t> path(32768);DWORD length=static_cast<DWORD>(path.size());
        if(!QueryFullProcessImageNameW(proc.h,0,path.data(),&length))continue;
        std::wstring image(path.data(),length);
        // Do not terminate operating-system processes even if configured by mistake.
        wchar_t root[MAX_PATH]{};UINT n=GetWindowsDirectoryW(root,MAX_PATH);
        if(n>0&&n<MAX_PATH&&image.size()>n&&_wcsnicmp(image.c_str(),root,n)==0&&(image[n]==L'\\'||image[n]==L'/'))continue;
        auto hash=file_hash(image);if(hash.empty()||std::find(blocked.begin(),blocked.end(),hash)==blocked.end())continue;
        if(TerminateProcess(proc.h,ERROR_ACCESS_DISABLED_BY_POLICY)){stopped.push_back(hash);show_notice(pid);}
    }while(Process32NextW(snapshot.h,&entry));
    return stopped;
}
