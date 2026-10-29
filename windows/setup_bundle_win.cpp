#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <algorithm>
#include <string>
#include <vector>
#include "setup_bundle.hpp"

namespace ohno {
BootstrapResult read_school_bundle(SchoolBootstrap& config) {
    std::vector<wchar_t> name(32768);
    DWORD count=GetModuleFileNameW(nullptr,name.data(),static_cast<DWORD>(name.size()));
    if(!count || count>=name.size()) return BootstrapResult::Invalid;
    HANDLE file=CreateFileW(name.data(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,
                            nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE) return BootstrapResult::Invalid;
    LARGE_INTEGER size{};
    if(!GetFileSizeEx(file,&size) || size.QuadPart<16) {
        CloseHandle(file);return BootstrapResult::Invalid;
    }
    constexpr DWORD max_tail=16+1024+16384;
    DWORD wanted=static_cast<DWORD>(std::min<LONGLONG>(size.QuadPart,max_tail));
    LARGE_INTEGER start{};start.QuadPart=size.QuadPart-wanted;
    if(!SetFilePointerEx(file,start,nullptr,FILE_BEGIN)){
        CloseHandle(file);return BootstrapResult::Invalid;
    }
    std::string tail(wanted,'\0');
    DWORD got=0;
    bool ok=ReadFile(file,tail.data(),wanted,&got,nullptr)!=FALSE && got==wanted;
    CloseHandle(file);
    if(!ok)return BootstrapResult::Invalid;
    return decode_school_bundle(tail,config);
}
}
