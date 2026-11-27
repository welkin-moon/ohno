#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <wtsapi32.h>
#include <wincrypt.h>
#include <winver.h>
#include <string>
#include <cwchar>
#include <vector>
#include <algorithm>
#include <map>
#include "monitor.hpp"
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
namespace {
struct handle { HANDLE h=INVALID_HANDLE_VALUE; ~handle(){if(h&&h!=INVALID_HANDLE_VALUE) CloseHandle(h);} };
struct algorithm { BCRYPT_ALG_HANDLE h=nullptr; ~algorithm(){if(h) BCryptCloseAlgorithmProvider(h,0);} };
struct hash_handle { BCRYPT_HASH_HANDLE h=nullptr; ~hash_handle(){if(h) BCryptDestroyHash(h);} };
struct file_stamp { BY_HANDLE_FILE_INFORMATION info{}; FILE_BASIC_INFO basic{}; };
bool read_stamp(HANDLE file,file_stamp& stamp){
    return GetFileInformationByHandle(file,&stamp.info)&&
        GetFileInformationByHandleEx(file,FileBasicInfo,&stamp.basic,sizeof(stamp.basic));
}
bool same_stamp(const file_stamp& a,const file_stamp& b){
    return a.info.dwVolumeSerialNumber==b.info.dwVolumeSerialNumber&&
        a.info.nFileIndexHigh==b.info.nFileIndexHigh&&a.info.nFileIndexLow==b.info.nFileIndexLow&&
        a.info.nFileSizeHigh==b.info.nFileSizeHigh&&a.info.nFileSizeLow==b.info.nFileSizeLow&&
        CompareFileTime(&a.info.ftLastWriteTime,&b.info.ftLastWriteTime)==0&&
        a.basic.ChangeTime.QuadPart==b.basic.ChangeTime.QuadPart;
}
std::string to_utf8(const std::wstring& w){
    if(w.empty())return {};
    int n=WideCharToMultiByte(CP_UTF8,0,w.data(),static_cast<int>(w.size()),nullptr,0,nullptr,nullptr);
    if(n<=0)return {};
    std::string out(static_cast<std::size_t>(n),'\0');
    if(!WideCharToMultiByte(CP_UTF8,0,w.data(),static_cast<int>(w.size()),out.data(),n,nullptr,nullptr))return {};
    return out;
}
std::wstring from_utf8(const std::string& s){
    if(s.empty())return {};
    int n=MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0);
    if(n<=0)return {};
    std::wstring out(static_cast<std::size_t>(n),L'\0');
    if(!MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),out.data(),n))return {};
    return out;
}
std::string query_version_string(const void* ver_data,const std::wstring& lang_cp,const wchar_t* field){
    std::wstring sub=L"\\StringFileInfo\\"+lang_cp+L"\\"+field;
    LPWSTR ptr=nullptr;UINT len=0;
    if(VerQueryValueW(ver_data,sub.c_str(),reinterpret_cast<LPVOID*>(&ptr),&len)&&ptr&&len>0){
        std::wstring val(ptr,wcsnlen(ptr,len));
        return to_utf8(val);
    }
    return {};
}
void read_pe_version_info(const std::wstring& path,ohno::ProcessFeatures& out){
    DWORD dummy=0;
    DWORD sz=GetFileVersionInfoSizeW(path.c_str(),&dummy);
    if(!sz||sz>4*1024*1024)return;
    std::vector<BYTE> data(sz);
    if(!GetFileVersionInfoW(path.c_str(),0,sz,data.data()))return;
    struct LangCP { WORD lang; WORD cp; };
    std::vector<std::wstring> locales;
    LangCP* trans=nullptr;UINT trans_bytes=0;
    if(VerQueryValueW(data.data(),L"\\VarFileInfo\\Translation",reinterpret_cast<LPVOID*>(&trans),&trans_bytes)&&trans){
        for(UINT i=0;i<trans_bytes/sizeof(LangCP)&&i<8;++i){
            wchar_t buf[16]{};
            swprintf_s(buf,L"%04x%04x",trans[i].lang,trans[i].cp);
            locales.emplace_back(buf);
        }
    }
    locales.emplace_back(L"040904b0");
    locales.emplace_back(L"080404b0");
    locales.emplace_back(L"040904e4");
    auto pick=[&](const wchar_t* field)->std::string{
        for(const auto& loc:locales){
            auto v=query_version_string(data.data(),loc,field);
            if(!v.empty())return v;
        }
        return {};
    };
    out.orig_filename=pick(L"OriginalFilename");
    out.product_name=pick(L"ProductName");
    out.file_description=pick(L"FileDescription");
    out.company_name=pick(L"CompanyName");
    out.internal_name=pick(L"InternalName");
}
std::string read_authenticode_signer(const std::wstring& path){
    HCERTSTORE store=nullptr;HCRYPTMSG msg=nullptr;
    if(!CryptQueryObject(CERT_QUERY_OBJECT_FILE,path.c_str(),CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBEDDED,
                         CERT_QUERY_FORMAT_FLAG_BINARY,0,nullptr,nullptr,nullptr,&store,&msg,nullptr))
        return {};
    std::string signer;
    if(store&&msg){
        DWORD info_size=0;
        if(CryptMsgGetParam(msg,CMSG_SIGNER_INFO_PARAM,0,nullptr,&info_size)&&info_size>0&&info_size<65536){
            std::vector<BYTE> buf(info_size);
            if(CryptMsgGetParam(msg,CMSG_SIGNER_INFO_PARAM,0,buf.data(),&info_size)){
                auto* si=reinterpret_cast<PCMSG_SIGNER_INFO>(buf.data());
                CERT_INFO ci{};ci.Issuer=si->Issuer;ci.SerialNumber=si->SerialNumber;
                PCCERT_CONTEXT cert=CertFindCertificateInStore(store,X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,0,CERT_FIND_SUBJECT_CERT,&ci,nullptr);
                if(cert){
                    wchar_t name[256]{};
                    DWORD got=CertGetNameStringW(cert,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,nullptr,name,256);
                    if(got>1)signer=to_utf8(std::wstring(name,got-1));
                    CertFreeCertificateContext(cert);
                }
            }
        }
    }
    if(msg)CryptMsgClose(msg);
    if(store)CertCloseStore(store,0);
    return signer;
}
std::map<DWORD,std::string> collect_window_titles(){
    std::map<DWORD,std::string> titles;
    EnumWindows([](HWND hwnd,LPARAM lp)->BOOL{
        if(!IsWindowVisible(hwnd))return TRUE;
        int len=GetWindowTextLengthW(hwnd);
        if(len<=0||len>256)return TRUE;
        DWORD pid=0;GetWindowThreadProcessId(hwnd,&pid);
        if(!pid)return TRUE;
        std::vector<wchar_t> buf(static_cast<std::size_t>(len)+1,0);
        int got=GetWindowTextW(hwnd,buf.data(),len+1);
        if(got<=0)return TRUE;
        auto* map=reinterpret_cast<std::map<DWORD,std::string>*>(lp);
        auto t=to_utf8(std::wstring(buf.data(),static_cast<std::size_t>(got)));
        auto& entry=(*map)[pid];
        if(entry.size()+t.size()<512){
            if(!entry.empty())entry+=" | ";
            entry+=t;
        }
        return TRUE;
    },reinterpret_cast<LPARAM>(&titles));
    return titles;
}
bool path_under_dir(const std::wstring& image,const std::wstring& dir){
    if(dir.empty()||image.size()<=dir.size())return false;
    return _wcsnicmp(image.c_str(),dir.c_str(),dir.size())==0&&(image[dir.size()]==L'\\'||image[dir.size()]==L'/');
}
std::wstring self_install_root(){
    std::vector<wchar_t> path(32768);
    DWORD n=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if(!n||n>=path.size())return {};
    std::wstring p(path.data(),n);
    auto slash=p.find_last_of(L"\\/");
    if(slash==std::wstring::npos)return {};
    std::wstring base=p.substr(slash+1);
    if(_wcsicmp(base.c_str(),L"ohno-service.exe")!=0&&_wcsicmp(base.c_str(),L"ohno-worker.exe")!=0)return {};
    std::wstring dir=p.substr(0,slash);
    // If running inside Program Files\Ohno\versions\<rev>, protect the whole Ohno install root.
    auto vpos=dir.rfind(L"\\versions\\");
    if(vpos!=std::wstring::npos)return dir.substr(0,vpos);
    return dir;
}
}
std::string program_image_hash(const std::wstring& path,HANDLE stop_event) {
    if(stop_event&&WaitForSingleObject(stop_event,0)==WAIT_OBJECT_0)return {};
    // Keep writers and renames out while reading; an unverified hash must not
    // inherit an exception just because the path, size and mtime were reused.
    handle file{CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,nullptr)};
    if(file.h==INVALID_HANDLE_VALUE)return {};
    file_stamp before;if(!read_stamp(file.h,before))return {};
    const auto& info=before.info;
    ULONGLONG size=(static_cast<ULONGLONG>(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
    // Avoid hashing enormous or special files on a classroom computer.
    if(size>512ULL*1024*1024)return {};
    // Metadata is not a content generation: NTFS ChangeTime can coincide for
    // rapid equal-size rewrites, even when mtime is explicitly restored. Never
    // reuse a previous digest to grant an exception from metadata alone.
    // Hash the bytes under this writer/rename-denying handle on every call.
    algorithm alg;if(BCryptOpenAlgorithmProvider(&alg.h,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)return {};
    DWORD object_size=0,got=0;if(BCryptGetProperty(alg.h,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&object_size),sizeof(object_size),&got,0)<0)return {};
    std::vector<unsigned char> object(object_size);hash_handle hash;
    if(BCryptCreateHash(alg.h,&hash.h,object.data(),object_size,nullptr,0,0)<0)return {};
    std::vector<unsigned char> buf(65536);DWORD n=0;
    do {if(stop_event&&WaitForSingleObject(stop_event,0)==WAIT_OBJECT_0)return {};if(!ReadFile(file.h,buf.data(),static_cast<DWORD>(buf.size()),&n,nullptr))return {};if(n&&BCryptHashData(hash.h,buf.data(),n,0)<0)return {};}while(n);
    unsigned char digest[32]{};if(BCryptFinishHash(hash.h,digest,sizeof(digest),0)<0)return {};
    file_stamp after;if(!read_stamp(file.h,after)||!same_stamp(before,after))return {};
    const char* hex="0123456789abcdef";std::string out;out.reserve(64);for(auto b:digest){out+=hex[b>>4];out+=hex[b&15];}
    return out;
}
ohno::ProcessFeatures extract_process_features(DWORD pid,const std::wstring& image_path){
    ohno::ProcessFeatures f;
    f.full_path=to_utf8(image_path);
    auto slash=image_path.find_last_of(L"\\/");
    f.exe_name=to_utf8(slash==std::wstring::npos?image_path:image_path.substr(slash+1));
    read_pe_version_info(image_path,f);
    f.signer=read_authenticode_signer(image_path);
    if(pid){
        auto titles=collect_window_titles();
        auto it=titles.find(pid);
        if(it!=titles.end())f.window_title=it->second;
    }
    return f;
}
namespace {
void show_notice(DWORD pid,bool whitelist){
    DWORD session=0;if(!ProcessIdToSessionId(pid,&session)||session==0)return;
    wchar_t title[]=L"ohno 课堂助手";
    wchar_t msg_bl[]=L"此程序暂时被课堂规则限制，请联系教师。";
    wchar_t msg_wl[]=L"当前处于白名单课堂模式，未授权程序已被限制，请联系教师。";
    wchar_t* message=whitelist?msg_wl:msg_bl;
    DWORD result=0;WTSSendMessageW(WTS_CURRENT_SERVER_HANDLE,session,title,static_cast<DWORD>(wcslen(title)*sizeof(wchar_t)),message,static_cast<DWORD>(wcslen(message)*sizeof(wchar_t)),MB_OK|MB_ICONINFORMATION,15,&result,FALSE);
}
}
std::vector<BlockedProgram> stop_matching_processes(const ohno::ProcessRuleSet& rules,DWORD only_pid,HANDLE stop_event){
    std::vector<BlockedProgram> stopped;
    const bool whitelist=rules.mode==ohno::PolicyMode::Whitelist;
    if(!whitelist&&rules.block_hashes.empty()&&rules.block_names.empty()&&rules.block_features.empty())return stopped;

    wchar_t win_dir_buf[MAX_PATH]{};
    UINT win_len=GetWindowsDirectoryW(win_dir_buf,MAX_PATH);
    std::wstring win_dir(win_len>0&&win_len<MAX_PATH?win_dir_buf:L"");
    std::wstring ohno_dir=self_install_root();

    // Collect visible top-level window titles once per scan cycle when needed.
    const bool need_features=whitelist?!rules.allow_features.empty():!rules.block_features.empty();
    std::map<DWORD,std::string> titles;
    if(need_features)titles=collect_window_titles();

    handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)};if(snapshot.h==INVALID_HANDLE_VALUE)return stopped;
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);
    if(!Process32FirstW(snapshot.h,&entry))return stopped;
    const DWORD self_pid=GetCurrentProcessId();
    do {
        if(stop_event&&WaitForSingleObject(stop_event,0)==WAIT_OBJECT_0)break;
        DWORD pid=entry.th32ProcessID;
        if((only_pid&&pid!=only_pid)||pid==0||pid==4||pid==self_pid)continue;

        // In whitelist mode, never terminate Session-0 background system services.
        DWORD session=0;
        const bool have_session=ProcessIdToSessionId(pid,&session)!=FALSE;
        if(whitelist&&(!have_session||session==0)&&only_pid==0)continue;

        // Fast skip in blacklist mode when no hashes/features exist and filename doesn't match.
        std::string exe_utf8=to_utf8(entry.szExeFile);
        if(!whitelist&&rules.block_hashes.empty()&&rules.block_features.empty()&&
           !ohno::matches_any_name(exe_utf8,rules.block_names))continue;

        handle proc{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE,FALSE,pid)};if(!proc.h)continue;
        std::vector<wchar_t> path(32768);DWORD length=static_cast<DWORD>(path.size());
        if(!QueryFullProcessImageNameW(proc.h,0,path.data(),&length))continue;
        std::wstring image(path.data(),length);

        // Protect OS processes (C:\Windows) and Ohno's own binaries in ALL modes.
        const bool is_protected=path_under_dir(image,win_dir)||path_under_dir(image,ohno_dir);
        if(is_protected)continue;

        ohno::ProcessFeatures feat;
        feat.exe_name=exe_utf8;
        feat.full_path=to_utf8(image);
        if(need_features){
            read_pe_version_info(image,feat);
            feat.signer=read_authenticode_signer(image);
            auto it=titles.find(pid);
            if(it!=titles.end())feat.window_title=it->second;
        }

        // Fast check without hashing if possible:
        // - In blacklist mode without block_hashes: if neither name nor feature matched, skip hashing!
        // - In whitelist mode: if name or feature is already whitelisted, skip hashing!
        if(!whitelist){
            const bool matched_meta=ohno::matches_any_name(feat.exe_name,rules.block_names)||
                                    ohno::matches_any_feature(feat,rules.block_features);
            if(!matched_meta&&rules.block_hashes.empty())continue;
        }else{
            if(ohno::matches_any_name(feat.exe_name,rules.allow_names)||
               ohno::matches_any_feature(feat,rules.allow_features))continue;
        }

        auto hash=program_image_hash(image,stop_event);
        if(stop_event&&WaitForSingleObject(stop_event,0)==WAIT_OBJECT_0)break;
        if(!ohno::should_block_process(rules,feat,hash,false))continue;

        if(TerminateProcess(proc.h,ERROR_ACCESS_DISABLED_BY_POLICY)){
            std::wstring label=entry.szExeFile;
            if(!feat.product_name.empty()&&!ohno::contains_icase(feat.exe_name,feat.product_name)){
                label+=L" ("+from_utf8(feat.product_name)+L")";
            }else if(!feat.orig_filename.empty()&&!ohno::equals_icase(feat.exe_name,feat.orig_filename)){
                label+=L" ("+from_utf8(feat.orig_filename)+L")";
            }
            stopped.push_back({hash,label});
            show_notice(pid,whitelist);
        }
    }while(Process32NextW(snapshot.h,&entry));
    return stopped;
}
std::vector<BlockedProgram> stop_matching_processes(const std::vector<std::string>& blocked,const std::vector<std::string>& names,const std::vector<std::string>& allowed,DWORD only_pid,HANDLE stop_event){
    ohno::ProcessRuleSet rules;
    rules.mode=ohno::PolicyMode::Blacklist;
    rules.block_hashes=blocked;
    rules.block_names=names;
    rules.temp_allowed_hashes=allowed;
    return stop_matching_processes(rules,only_pid,stop_event);
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
std::vector<UntrustedProgram> observe_untrusted_programs(HANDLE stop_event){
    std::vector<UntrustedProgram> out;handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)};
    if(snapshot.h==INVALID_HANDLE_VALUE)return out;PROCESSENTRY32W e{};e.dwSize=sizeof(e);if(!Process32FirstW(snapshot.h,&e))return out;
    do{
        if(stop_event&&WaitForSingleObject(stop_event,0)==WAIT_OBJECT_0)break;
        if(e.th32ProcessID==0||e.th32ProcessID==4||e.th32ProcessID==GetCurrentProcessId())continue;
        handle proc{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,e.th32ProcessID)};if(!proc.h)continue;
        std::vector<wchar_t> buffer(32768);DWORD n=static_cast<DWORD>(buffer.size());if(!QueryFullProcessImageNameW(proc.h,0,buffer.data(),&n))continue;
        std::wstring path(buffer.data(),n);if(!is_removable(path)&&!has_download_zone(path))continue;
        auto hash=program_image_hash(path,stop_event);if(!hash.empty())out.push_back({path,hash,e.th32ProcessID});
    }while(Process32NextW(snapshot.h,&e));return out;
}

void notify_network_block(DWORD pid){
    DWORD session=0;if(!ProcessIdToSessionId(pid,&session)||session==0)return;
    wchar_t title[]=L"ohno 课堂助手";
    wchar_t message[]=L"检测到来自下载或可移动磁盘的程序。其新的联网请求已受限制，可联系教师审批。";
    DWORD result=0;WTSSendMessageW(WTS_CURRENT_SERVER_HANDLE,session,title,static_cast<DWORD>(wcslen(title)*sizeof(wchar_t)),message,static_cast<DWORD>(wcslen(message)*sizeof(wchar_t)),MB_OK|MB_ICONINFORMATION,15,&result,FALSE);
}
