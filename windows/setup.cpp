// Experimental standalone setup; not yet suitable for deployment.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>
#include "browser_policy.hpp"
#include "setup_bundle.hpp"
#include "setup_ui.hpp"
#include "maintenance_http.hpp"
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"winhttp.lib")
#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"bcrypt.lib")
namespace {
constexpr wchar_t service_name[]=L"OhnoPrototype";
constexpr wchar_t uninstall_key[]=L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OhnoPrototype";
bool password_stdin=false,reboot_cleanup_pending=false,authorization_cancelled=false;
struct secret_wide {std::wstring value;~secret_wide(){if(!value.empty())SecureZeroMemory(value.data(),value.size()*sizeof(wchar_t));}};
struct sc {SC_HANDLE h=nullptr;~sc(){if(h)CloseServiceHandle(h);}};
struct reg {HKEY h=nullptr;~reg(){if(h)RegCloseKey(h);}};
std::wstring directory(){PWSTR raw=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,0,nullptr,&raw)))return {};std::wstring p=raw;CoTaskMemFree(raw);return p+L"\\OhnoPrototype";}
bool valid_url(const wchar_t* url){for(auto p=url;*p;++p)if(*p<33||*p>126)return false;URL_COMPONENTSW c{};c.dwStructSize=sizeof(c);c.dwHostNameLength=DWORD(-1);c.dwUserNameLength=DWORD(-1);c.dwPasswordLength=DWORD(-1);c.dwUrlPathLength=DWORD(-1);c.dwExtraInfoLength=DWORD(-1);return WinHttpCrackUrl(url,0,0,&c)&&c.nScheme==INTERNET_SCHEME_HTTPS&&c.nPort!=0&&c.dwHostNameLength&&!c.dwUserNameLength&&!c.dwPasswordLength&&!c.dwExtraInfoLength&&c.dwUrlPathLength<=1;}
// This changes machine-wide certificate trust. School administrators must
// verify the teacher endpoint before distributing a personalized installer.
bool import_root_context(PCCERT_CONTEXT certificate,HKEY config){
    if(!certificate)return false;
    HCERTSTORE roots=CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_LOCAL_MACHINE,L"ROOT");
    if(!roots)return false;
    bool result=false;BYTE hash[20]{};DWORD size=sizeof(hash);
    if(CertCompareCertificateName(X509_ASN_ENCODING,&certificate->pCertInfo->Subject,&certificate->pCertInfo->Issuer)&&
        CertGetCertificateContextProperty(certificate,CERT_SHA1_HASH_PROP_ID,hash,&size)&&size==sizeof(hash)){
        CRYPT_HASH_BLOB blob{size,hash};
        PCCERT_CONTEXT existing=CertFindCertificateInStore(roots,X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,0,CERT_FIND_SHA1_HASH,&blob,nullptr);
        if(existing){CertFreeCertificateContext(existing);result=true;}
        else if(RegSetValueExW(config,L"ImportedRootSha1",0,REG_BINARY,hash,size)==ERROR_SUCCESS){
            if(CertAddCertificateContextToStore(roots,certificate,CERT_STORE_ADD_NEW,nullptr))result=true;
            else RegDeleteValueW(config,L"ImportedRootSha1");
        }
    }
    CertCloseStore(roots,0);
    return result;
}
bool import_root_pem(const std::string& pem,HKEY config){
    DWORD der_length=0;
    if(!CryptStringToBinaryA(pem.c_str(),static_cast<DWORD>(pem.size()),CRYPT_STRING_BASE64HEADER,
        nullptr,&der_length,nullptr,nullptr)||!der_length||der_length>16384)return false;
    std::vector<BYTE> der(der_length);
    if(!CryptStringToBinaryA(pem.c_str(),static_cast<DWORD>(pem.size()),CRYPT_STRING_BASE64HEADER,
        der.data(),&der_length,nullptr,nullptr))return false;
    PCCERT_CONTEXT cert=CertCreateCertificateContext(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,der.data(),der_length);
    if(!cert)return false;
    bool ok=import_root_context(cert,config);
    CertFreeCertificateContext(cert);return ok;
}
bool remove_imported_certificate(HKEY config){
    BYTE hash[20]{};DWORD size=sizeof(hash),type=0;
    LONG q=RegQueryValueExW(config,L"ImportedRootSha1",nullptr,&type,hash,&size);
    if(q==ERROR_FILE_NOT_FOUND)return true;
    if(q!=ERROR_SUCCESS||type!=REG_BINARY||size!=sizeof(hash))return false;
    HCERTSTORE roots=CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_LOCAL_MACHINE,L"ROOT");if(!roots)return false;
    CRYPT_HASH_BLOB blob{size,hash};PCCERT_CONTEXT cert=CertFindCertificateInStore(roots,X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,0,CERT_FIND_SHA1_HASH,&blob,nullptr);
    bool ok=cert?CertDeleteCertificateFromStore(cert)!=FALSE:true;CertCloseStore(roots,0);return ok;
}
bool embedded_exe(const std::wstring& path,int resource_id){
    HRSRC res=FindResourceW(nullptr,MAKEINTRESOURCEW(resource_id),RT_RCDATA);if(!res)return false;
    HGLOBAL data=LoadResource(nullptr,res);DWORD size=SizeofResource(nullptr,res);void* src=LockResource(data);if(!src||!size)return false;
    HANDLE f=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(f==INVALID_HANDLE_VALUE)return false;
    DWORD wrote=0;BOOL ok=WriteFile(f,src,size,&wrote,nullptr);CloseHandle(f);return ok&&wrote==size;
}
bool make_shortcut(const std::wstring& exe,std::wstring& created){
    PWSTR raw=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_PublicDesktop,0,nullptr,&raw)))return false;
    std::wstring path=raw;CoTaskMemFree(raw);path+=L"\\ohno website request.lnk";
    if(GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES)return true;
    HRESULT init=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);if(FAILED(init))return false;
    IShellLinkW* link=nullptr;IPersistFile* file=nullptr;bool ok=false;
    if(SUCCEEDED(CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,reinterpret_cast<void**>(&link)))){
        link->SetPath(exe.c_str());link->SetDescription(L"ohno website approval request");
        if(SUCCEEDED(link->QueryInterface(IID_IPersistFile,reinterpret_cast<void**>(&file)))){ok=SUCCEEDED(file->Save(path.c_str(),TRUE));file->Release();}link->Release();
    }
    CoUninitialize();if(ok)created=path;return ok;
}
void remove_shortcut(const std::wstring& shortcut,const std::wstring& expected){
    if(shortcut.empty()||expected.empty())return;
    PWSTR raw=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_PublicDesktop,0,nullptr,&raw)))return;
    std::wstring wanted=raw;CoTaskMemFree(raw);wanted+=L"\\ohno website request.lnk";
    if(_wcsicmp(shortcut.c_str(),wanted.c_str())!=0)return;
    HRESULT init=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);if(FAILED(init))return;
    IShellLinkW* link=nullptr;IPersistFile* file=nullptr;bool remove=false;
    if(SUCCEEDED(CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,reinterpret_cast<void**>(&link)))){
        if(SUCCEEDED(link->QueryInterface(IID_IPersistFile,reinterpret_cast<void**>(&file)))){
            if(SUCCEEDED(file->Load(shortcut.c_str(),STGM_READ))){wchar_t path[32768]{};if(SUCCEEDED(link->GetPath(path,32768,nullptr,SLGP_RAWPATH))&&_wcsicmp(path,expected.c_str())==0)remove=true;}file->Release();}link->Release();
    }
    CoUninitialize();if(remove)DeleteFileW(shortcut.c_str());
}
std::wstring read_config_string(HKEY key,const wchar_t* name){
    DWORD type=0,size=0;if(RegQueryValueExW(key,name,nullptr,&type,nullptr,&size)!=ERROR_SUCCESS||type!=REG_SZ||size>65536||size<sizeof(wchar_t)||size%sizeof(wchar_t))return {};
    std::vector<wchar_t> value(size/sizeof(wchar_t)+1,0);
    struct wipe_buffer {std::vector<wchar_t>& data;~wipe_buffer(){SecureZeroMemory(data.data(),data.size()*sizeof(wchar_t));}} wipe{value};
    if(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE*>(value.data()),&size)!=ERROR_SUCCESS||type!=REG_SZ||size%sizeof(wchar_t))return {};
    return std::wstring(value.data());
}
std::wstring module_path(){std::vector<wchar_t> name(32768);DWORD n=GetModuleFileNameW(nullptr,name.data(),static_cast<DWORD>(name.size()));return n&&n<name.size()?std::wstring(name.data(),n):L"";}
bool write_config(HKEY key,const wchar_t* name,const std::wstring& value){return RegSetValueExW(key,name,0,REG_SZ,reinterpret_cast<const BYTE*>(value.c_str()),static_cast<DWORD>((value.size()+1)*sizeof(wchar_t)))==ERROR_SUCCESS;}
bool certificate_pem_from_file(const wchar_t* path,std::string& pem){
    PCCERT_CONTEXT cert=nullptr;
    if(!CryptQueryObject(CERT_QUERY_OBJECT_FILE,path,CERT_QUERY_CONTENT_FLAG_CERT,CERT_QUERY_FORMAT_FLAG_ALL,0,
        nullptr,nullptr,nullptr,nullptr,nullptr,reinterpret_cast<const void**>(&cert))||!cert)return false;
    DWORD size=0;bool ok=CryptBinaryToStringA(cert->pbCertEncoded,cert->cbCertEncoded,CRYPT_STRING_BASE64HEADER,nullptr,&size)!=FALSE&&size<=16384;
    if(ok){pem.resize(size);ok=CryptBinaryToStringA(cert->pbCertEncoded,cert->cbCertEncoded,CRYPT_STRING_BASE64HEADER,pem.data(),&size)!=FALSE;if(ok){pem.resize(size);if(!pem.empty()&&pem.back()=='\0')pem.pop_back();}}
    CertFreeCertificateContext(cert);return ok;
}
bool get_password(const std::wstring& server,bool uninstall,std::string& output){
    if(password_stdin){
        output.reserve(512); // avoid stale plaintext copies on string growth
        HANDLE input=GetStdHandle(STD_INPUT_HANDLE);if(!input||input==INVALID_HANDLE_VALUE)return false;
        char ch=0;DWORD count=0;bool line=false;
        while(ReadFile(input,&ch,1,&count,nullptr)&&count){
            if(ch=='\n'){line=true;break;}if(output.size()>=512)return false;output+=ch;
        }
        if(!output.empty()&&output.back()=='\r')output.pop_back();
        return (line||count==0)&&!output.empty();
    }
    secret_wide entered;if(!ohno::prompt_maintenance_password(server,uninstall,entered.value))return false;
    const int length=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,entered.value.data(),static_cast<int>(entered.value.size()),nullptr,0,nullptr,nullptr);
    if(length<=0||length>512)return false;output.resize(static_cast<std::size_t>(length));
    return WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,entered.value.data(),static_cast<int>(entered.value.size()),output.data(),length,nullptr,nullptr)!=0;
}
bool authorize(const std::wstring& server,const std::string& pem,bool uninstall){
    ohno::MaintenanceRequest request;request.server=server;request.certificate_pem=pem;request.action=uninstall?"uninstall":"install";
    // Owned password/device secret buffers are transient and wiped on this path.
    struct wipe {ohno::MaintenanceRequest& r;~wipe(){if(!r.password.empty())SecureZeroMemory(r.password.data(),r.password.size());if(!r.device_key.empty())SecureZeroMemory(r.device_key.data(),r.device_key.size());}} cleanup{request};
    if(uninstall){
        reg identity;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno\\Identity",0,KEY_READ,&identity.h)!=ERROR_SUCCESS)return false;
        secret_wide credentials;credentials.value=read_config_string(identity.h,L"Credentials");
        const auto n=credentials.value.size();if(n<98||credentials.value[n-98]!=L':'||credentials.value[n-65]!=L':')return false;
        for(std::size_t i=n-97;i<n;++i)if(i!=n-65&&!((credentials.value[i]>=L'0'&&credentials.value[i]<=L'9')||(credentials.value[i]>=L'a'&&credentials.value[i]<=L'f')))return false;
        request.device_id.assign(credentials.value.begin()+static_cast<std::ptrdiff_t>(n-97),credentials.value.begin()+static_cast<std::ptrdiff_t>(n-65));
        request.device_key.assign(credentials.value.begin()+static_cast<std::ptrdiff_t>(n-64),credentials.value.end());
    }
    unsigned char nonce[32]{};if(BCryptGenRandom(nullptr,nonce,sizeof(nonce),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return false;
    constexpr char hex[]="0123456789abcdef";for(auto b:nonce){request.nonce+=hex[b>>4];request.nonce+=hex[b&15];}
    if(!get_password(server,uninstall,request.password)){authorization_cancelled=!password_stdin;return false;}
    const auto result=ohno::authorize_maintenance(request);
    if(result!=ohno::MaintenanceResult::Authorized){std::fwprintf(stderr,L"Teacher maintenance authorization failed; no install/remove changes made.\n");return false;}
    return true;
}
bool register_uninstaller(const std::wstring& dir,const std::wstring& executable,bool& created){
    reg key;DWORD disposition=0;
    if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,uninstall_key,0,nullptr,0,KEY_WRITE,nullptr,&key.h,&disposition)!=ERROR_SUCCESS||disposition!=REG_CREATED_NEW_KEY)return false;
    created=true;DWORD yes=1;
    return write_config(key.h,L"DisplayName",L"Ohno classroom assistant")&&write_config(key.h,L"Publisher",L"Ohno")&&
        write_config(key.h,L"InstallLocation",dir)&&write_config(key.h,L"UninstallString",L"\""+executable+L"\" --remove")&&
        RegSetValueExW(key.h,L"NoModify",0,REG_DWORD,reinterpret_cast<const BYTE*>(&yes),sizeof(yes))==ERROR_SUCCESS&&
        RegSetValueExW(key.h,L"NoRepair",0,REG_DWORD,reinterpret_cast<const BYTE*>(&yes),sizeof(yes))==ERROR_SUCCESS;
}
bool is_administrator(){
    SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY;PSID group=nullptr;BOOL member=FALSE;
    if(!AllocateAndInitializeSid(&authority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&group))return false;
    const bool ok=CheckTokenMembership(nullptr,group,&member)!=FALSE;FreeSid(group);return ok&&member;
}
int install(const wchar_t* url,const wchar_t* certificate_path,const std::string* embedded_pem=nullptr){
    if(!valid_url(url)){std::fwprintf(stderr,L"Expected an HTTPS origin, e.g. https://teacher.example:8443\n");return 2;}
    sc manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE)};if(!manager.h){std::fwprintf(stderr,L"Administrator access required (%lu)\n",GetLastError());return 1;}
    sc existing{OpenServiceW(manager.h,service_name,SERVICE_QUERY_STATUS)};if(existing.h){std::fwprintf(stderr,L"Service already exists.\n");return 1;}
    reg prior;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&prior.h)==ERROR_SUCCESS){std::fwprintf(stderr,L"Ohno registry key already exists.\n");return 1;}
    reg prior_uninstall;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,uninstall_key,0,KEY_READ,&prior_uninstall.h)==ERROR_SUCCESS){std::fwprintf(stderr,L"Ohno uninstall registration already exists.\n");return 1;}
    std::string pem=embedded_pem?*embedded_pem:std::string{};
    if(certificate_path&&!certificate_pem_from_file(certificate_path,pem)){std::fwprintf(stderr,L"Cannot read teacher public certificate.\n");return 1;}
    if(!authorize(url,pem,false))return authorization_cancelled?2:1;
    std::wstring dir=directory();if(dir.empty()||!CreateDirectoryW(dir.c_str(),nullptr)){std::fwprintf(stderr,L"Cannot create program directory (%lu)\n",GetLastError());return 1;}
    std::wstring exe=dir+L"\\ohno-service.exe",helper=dir+L"\\ohno-request.exe",tun=dir+L"\\ohno-tun.exe",gpl=dir+L"\\sing-box-LICENSE.txt",wintun=dir+L"\\wintun-LICENSE.txt",shortcut;bool made_key=false;bool made_service=false;bool made_uninstaller=false;int result=1;
    const std::wstring maintenance=dir+L"\\ohno-maintenance.exe";
    do{
        if(!CopyFileW(module_path().c_str(),maintenance.c_str(),TRUE)||!embedded_exe(exe,101)||!embedded_exe(helper,102)||!embedded_exe(tun,103)||!embedded_exe(gpl,105)||!embedded_exe(wintun,106)){std::fwprintf(stderr,L"Cannot extract service (%lu)\n",GetLastError());break;}
        reg config;DWORD disposition=0;
        if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,nullptr,0,KEY_WRITE,nullptr,&config.h,&disposition)!=ERROR_SUCCESS||disposition!=REG_CREATED_NEW_KEY){std::fwprintf(stderr,L"Cannot create configuration.\n");break;}
        made_key=true;
        if(RegSetValueExW(config.h,L"ServerUrl",0,REG_SZ,reinterpret_cast<const BYTE*>(url),static_cast<DWORD>((wcslen(url)+1)*sizeof(wchar_t)))!=ERROR_SUCCESS){std::fwprintf(stderr,L"Cannot write configuration.\n");break;}
        if(!pem.empty()&&!write_config(config.h,L"TeacherCertificatePem",std::wstring(pem.begin(),pem.end()))){std::fwprintf(stderr,L"Cannot save public teacher certificate.\n");break;}
        if(!register_uninstaller(dir,maintenance,made_uninstaller)){std::fwprintf(stderr,L"Cannot register uninstaller.\n");break;}
        if(!make_shortcut(helper,shortcut)){std::fwprintf(stderr,L"Cannot create request shortcut.\n");break;}
        if(!shortcut.empty()&&RegSetValueExW(config.h,L"Shortcut",0,REG_SZ,reinterpret_cast<const BYTE*>(shortcut.c_str()),static_cast<DWORD>((shortcut.size()+1)*sizeof(wchar_t)))!=ERROR_SUCCESS){std::fwprintf(stderr,L"Cannot record request shortcut.\n");break;}
        if(!pem.empty()&&!import_root_pem(pem,config.h)){std::fwprintf(stderr,L"Cannot import teacher certificate (%lu)\n",GetLastError());break;}
        std::wstring quoted=L"\""+exe+L"\"";
        sc svc{CreateServiceW(manager.h,service_name,L"ohno prototype",SERVICE_ALL_ACCESS,SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,quoted.c_str(),nullptr,nullptr,nullptr,nullptr,nullptr)};
        if(!svc.h){std::fwprintf(stderr,L"Cannot register service (%lu)\n",GetLastError());break;}
        made_service=true;
        SC_ACTION actions[]={{SC_ACTION_RESTART,3000},{SC_ACTION_RESTART,10000},{SC_ACTION_NONE,0}};
        SERVICE_FAILURE_ACTIONSW recovery{};recovery.dwResetPeriod=3600;recovery.cActions=3;recovery.lpsaActions=actions;
        if(!ChangeServiceConfig2W(svc.h,SERVICE_CONFIG_FAILURE_ACTIONS,&recovery)){std::fwprintf(stderr,L"Cannot configure recovery (%lu)\n",GetLastError());DeleteService(svc.h);made_service=false;break;}
        if(!StartServiceW(svc.h,0,nullptr)){std::fwprintf(stderr,L"Cannot start service (%lu)\n",GetLastError());DeleteService(svc.h);made_service=false;break;}
        std::wprintf(L"Prototype installed. Approve the device in the teacher UI.\n");result=0;
    }while(false);
    if(result){if(made_uninstaller)RegDeleteTreeW(HKEY_LOCAL_MACHINE,uninstall_key);DeleteFileW(maintenance.c_str());if(made_service){sc svc{OpenServiceW(manager.h,service_name,DELETE)};if(svc.h)DeleteService(svc.h);}if(made_key){reg cfg;bool ok=true;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&cfg.h)==ERROR_SUCCESS)ok=remove_imported_certificate(cfg.h);if(ok)RegDeleteTreeW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno");else std::fwprintf(stderr,L"Certificate cleanup failed; registry record retained.\n");}remove_shortcut(shortcut,helper);DeleteFileW(wintun.c_str());DeleteFileW(gpl.c_str());DeleteFileW(tun.c_str());DeleteFileW(helper.c_str());DeleteFileW(exe.c_str());RemoveDirectoryW(dir.c_str());}
    return result;
}
int remove(bool administrator_recovery=false){
    if(administrator_recovery&&!is_administrator()){std::fwprintf(stderr,L"Administrator recovery requires an elevated OS administrator.\n");return 1;}
    std::wstring dir=directory();if(dir.empty())return 1;
    if(!administrator_recovery){
        reg config;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&config.h)!=ERROR_SUCCESS)return 1;
        const auto server=read_config_string(config.h,L"ServerUrl"),public_pem=read_config_string(config.h,L"TeacherCertificatePem");
        if(server.empty()||!authorize(server,std::string(public_pem.begin(),public_pem.end()),true))return authorization_cancelled?2:1;
    }else std::fwprintf(stderr,L"Explicit OS-administrator recovery removal; teacher authorization bypassed.\n");
    sc manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT)};if(!manager.h)return 1;
    sc svc{OpenServiceW(manager.h,service_name,SERVICE_STOP|SERVICE_QUERY_STATUS|DELETE)};
    if(!svc.h&&(!administrator_recovery||GetLastError()!=ERROR_SERVICE_DOES_NOT_EXIST)){std::fwprintf(stderr,L"Cannot open service (%lu)\n",GetLastError());return 1;}
    if(svc.h){
        SERVICE_STATUS status{};ControlService(svc.h,SERVICE_CONTROL_STOP,&status);
        for(int i=0;i<40;++i){if(!QueryServiceStatus(svc.h,&status))return 1;if(status.dwCurrentState==SERVICE_STOPPED)break;Sleep(500);}
        if(status.dwCurrentState!=SERVICE_STOPPED){std::fwprintf(stderr,L"Service did not stop; no files removed.\n");return 1;}
    }
    if(!clear_edge_policy()||!clear_edge_allow_policy()){std::fwprintf(stderr,L"Could not restore Edge URL policy; service retained.\n");return 1;}
    reg cfg;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&cfg.h)==ERROR_SUCCESS&&!remove_imported_certificate(cfg.h)){std::fwprintf(stderr,L"Could not remove imported teacher certificate; service retained.\n");return 1;}
    std::wstring shortcut=cfg.h?read_config_string(cfg.h,L"Shortcut"):L"";
    if(svc.h&&!DeleteService(svc.h)){std::fwprintf(stderr,L"Cannot delete service (%lu)\n",GetLastError());return 1;}
    std::wstring exe=dir+L"\\ohno-service.exe",helper=dir+L"\\ohno-request.exe";
    remove_shortcut(shortcut,helper);
    DeleteFileW((dir+L"\\ohno-tun.json").c_str());DeleteFileW((dir+L"\\ohno-tun.json.tmp").c_str());
    DeleteFileW((dir+L"\\wintun-LICENSE.txt").c_str());DeleteFileW((dir+L"\\sing-box-LICENSE.txt").c_str());
    DeleteFileW((dir+L"\\ohno-tun.exe").c_str());
    if(!DeleteFileW(helper.c_str()))std::fwprintf(stderr,L"Could not remove request helper (%lu).\n",GetLastError());
    if(!DeleteFileW(exe.c_str()))std::fwprintf(stderr,L"Could not remove service executable (%lu); remove manually after reboot.\n",GetLastError());
    const auto maintenance=dir+L"\\ohno-maintenance.exe";
    if(!DeleteFileW(maintenance.c_str())&&GetLastError()!=ERROR_FILE_NOT_FOUND){
        const auto self=module_path();
        if(_wcsicmp(self.c_str(),maintenance.c_str())==0&&MoveFileExW(maintenance.c_str(),nullptr,MOVEFILE_DELAY_UNTIL_REBOOT))reboot_cleanup_pending=true;
        else std::fwprintf(stderr,L"Could not remove maintenance executable; inspect manually.\n");
    }
    const auto removed_entry=RegDeleteTreeW(HKEY_LOCAL_MACHINE,uninstall_key);
    if(removed_entry!=ERROR_SUCCESS&&removed_entry!=ERROR_FILE_NOT_FOUND)std::fwprintf(stderr,L"Could not remove uninstall registration; inspect manually.\n");
    if(!RemoveDirectoryW(dir.c_str()))std::fwprintf(stderr,L"Could not remove program folder (%lu); inspect manually.\n",GetLastError());
    if(RegDeleteTreeW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno")!=ERROR_SUCCESS)std::fwprintf(stderr,L"Could not remove registry settings; inspect manually.\n");
    return 0;
}
}
int wmain(int argc,wchar_t** argv){
    std::vector<wchar_t*> args;args.push_back(argv[0]);
    for(int i=1;i<argc;++i){if(std::wcscmp(argv[i],L"--password-stdin")==0){if(password_stdin)return 2;password_stdin=true;}else args.push_back(argv[i]);}
    argc=static_cast<int>(args.size());argv=args.data();
    if(argc==1 || (argc==2&&std::wcscmp(argv[1],L"--install-bundled")==0)){
        ohno::SchoolBootstrap config;
        const auto result=ohno::read_school_bundle(config);
        if(result==ohno::BootstrapResult::Ready){
            const int code=install(config.server.c_str(),nullptr,&config.certificate_pem);
            if(argc==1&&!password_stdin&&code!=2)MessageBoxW(nullptr,
                code==0?L"Ohno 已安装，服务已自动启动。请在教师端批准设备。":
                L"Ohno 安装失败，请检查系统服务与程序目录，或联系学校 IT。",
                L"Ohno 学生端",MB_OK|(code==0?MB_ICONINFORMATION:MB_ICONERROR));
            return code;
        }
        if(argc==2 || result==ohno::BootstrapResult::Invalid){
            if(argc==1&&!password_stdin)MessageBoxW(nullptr,L"学校专属安装包配置损坏。请重新从教师端下载。",
                L"Ohno",MB_OK|MB_ICONERROR);
            return 1;
        }
        // Official generic download: a small native window, never a terminal.
        // School-issued EXEs have the embedded configuration and skip this UI.
        return ohno::show_install_wizard(
            [](const wchar_t* url,const wchar_t* cert)->int{return install(url,cert);});
    }
    if(argc==3&&std::wcscmp(argv[1],L"--install")==0)return install(argv[2],nullptr);
    if(argc==5&&std::wcscmp(argv[1],L"--install")==0&&std::wcscmp(argv[3],L"--certificate")==0)return install(argv[2],argv[4]);
    if(argc==2&&std::wcscmp(argv[1],L"--remove")==0){
        const int result=remove();
        if(!password_stdin&&result!=2)MessageBoxW(nullptr,result==0?(reboot_cleanup_pending?L"Ohno 已卸载。维护器自身文件将在重启后清理。":L"Ohno 已卸载。"):
            L"未能卸载。请检查教师维护密码、教师端网络和设备登记。学校 OS 管理员可使用明确的恢复移除命令。",L"Ohno",MB_OK|(result==0?MB_ICONINFORMATION:MB_ICONERROR));
        return result;
    }
    if(argc==2&&!password_stdin&&std::wcscmp(argv[1],L"--admin-recovery-remove")==0)return remove(true);
    std::fwprintf(stderr,L"Usage: double-click Ohno-School-Setup.exe, or --install HTTPS_ORIGIN [--certificate FILE] [--password-stdin], --remove [--password-stdin], --admin-recovery-remove\n");
    return 2;
}
