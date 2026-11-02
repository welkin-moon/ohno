#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cwchar>
#include <string>
#include <vector>
#include <stdexcept>
namespace ohno {
// Read-only ancestor pin for launchers. No lock/state creation or ACL changes.
// Installation must already be local NTFS with admin/SYSTEM-only write access.
class TrustedDirectory {
    std::vector<HANDLE> handles;
public:
    explicit TrustedDirectory(const std::wstring& root){
        try{
            if(root.size()<=3||root.size()>=240||root[1]!=L':'||root[2]!=L'\\'||root.find(L'/')!=std::wstring::npos||root.find(L':',2)!=std::wstring::npos)
                throw std::runtime_error("untrusted installation path");
            wchar_t full[32768]{};const auto size=GetFullPathNameW(root.c_str(),32768,full,nullptr);wchar_t fs[32]{};
            if(!size||size>=32768||root!=full||root.back()==L'\\'||!GetVolumeInformationW(root.substr(0,3).c_str(),nullptr,0,nullptr,nullptr,nullptr,fs,32)||_wcsicmp(fs,L"NTFS"))throw std::runtime_error("untrusted installation volume");
            for(std::size_t end=3;;){
                HANDLE h=CreateFileW(root.substr(0,end).c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
                if(h==INVALID_HANDLE_VALUE)throw std::runtime_error("installation ancestor");handles.push_back(h);BY_HANDLE_FILE_INFORMATION info{};
                if(!GetFileInformationByHandle(h,&info)||!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("installation reparse point");
                if(end==root.size())break;auto next=root.find(L'\\',end+1);end=next==std::wstring::npos?root.size():next;
            }
        }catch(...){for(auto h:handles)CloseHandle(h);throw;}
    }
    ~TrustedDirectory(){for(auto h:handles)CloseHandle(h);}
    TrustedDirectory(const TrustedDirectory&)=delete;TrustedDirectory& operator=(const TrustedDirectory&)=delete;
};
}
