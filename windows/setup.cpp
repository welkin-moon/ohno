// Experimental standalone setup; not yet suitable for deployment.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <cstdio>
#include <cwchar>
#include <string>
#include "browser_policy.hpp"
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"winhttp.lib")
#pragma comment(lib,"crypt32.lib")
namespace {
constexpr wchar_t service_name[]=L"OhnoPrototype";
struct sc {SC_HANDLE h=nullptr;~sc(){if(h)CloseServiceHandle(h);}};
struct reg {HKEY h=nullptr;~reg(){if(h)RegCloseKey(h);}};
std::wstring directory(){PWSTR raw=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,0,nullptr,&raw)))return {};std::wstring p=raw;CoTaskMemFree(raw);return p+L"\\OhnoPrototype";}
bool valid_url(const wchar_t* url){URL_COMPONENTSW c{};c.dwStructSize=sizeof(c);c.dwHostNameLength=DWORD(-1);c.dwUserNameLength=DWORD(-1);c.dwPasswordLength=DWORD(-1);c.dwUrlPathLength=DWORD(-1);c.dwExtraInfoLength=DWORD(-1);return WinHttpCrackUrl(url,0,0,&c)&&c.nScheme==INTERNET_SCHEME_HTTPS&&c.dwHostNameLength&&!c.dwUserNameLength&&!c.dwPasswordLength&&!c.dwExtraInfoLength&&c.dwUrlPathLength<=1;}
bool import_root_certificate(const wchar_t* path,HKEY config){
    DWORD encoding=0,content=0,format=0;PCCERT_CONTEXT certificate=nullptr;
    if(!CryptQueryObject(CERT_QUERY_OBJECT_FILE,path,CERT_QUERY_CONTENT_FLAG_CERT,CERT_QUERY_FORMAT_FLAG_ALL,0,&encoding,&content,&format,nullptr,nullptr,reinterpret_cast<const void**>(&certificate))||!certificate)return false;
    HCERTSTORE roots=CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_LOCAL_MACHINE,L"ROOT");
    if(!roots){CertFreeCertificateContext(certificate);return false;}
    bool result=false;BYTE hash[20]{};DWORD size=sizeof(hash);
    if(CertCompareCertificateName(encoding,&certificate->pCertInfo->Subject,&certificate->pCertInfo->Issuer)&&CertGetCertificateContextProperty(certificate,CERT_SHA1_HASH_PROP_ID,hash,&size)&&size==sizeof(hash)){
        CRYPT_HASH_BLOB blob{size,hash};
        PCCERT_CONTEXT existing=CertFindCertificateInStore(roots,X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,0,CERT_FIND_SHA1_HASH,&blob,nullptr);
        if(existing){CertFreeCertificateContext(existing);result=true;}
        else if(RegSetValueExW(config,L"ImportedRootSha1",0,REG_BINARY,hash,size)==ERROR_SUCCESS){
            if(CertAddCertificateContextToStore(roots,certificate,CERT_STORE_ADD_NEW,nullptr))result=true;
            else RegDeleteValueW(config,L"ImportedRootSha1");
        }
    }
    CertCloseStore(roots,0);CertFreeCertificateContext(certificate);return result;
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
    DWORD type=0,size=0;if(RegQueryValueExW(key,name,nullptr,&type,nullptr,&size)!=ERROR_SUCCESS||type!=REG_SZ||size>65536||size<sizeof(wchar_t))return {};
    std::wstring value(size/sizeof(wchar_t),L'\0');if(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE*>(value.data()),&size)!=ERROR_SUCCESS)return {};
    while(!value.empty()&&value.back()==L'\0')value.pop_back();return value;
}
int install(const wchar_t* url,const wchar_t* certificate_path){
    if(!valid_url(url)){std::fwprintf(stderr,L"Expected an HTTPS origin, e.g. https://teacher.example:8443\n");return 2;}
    sc manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE)};if(!manager.h){std::fwprintf(stderr,L"Administrator access required (%lu)\n",GetLastError());return 1;}
    sc existing{OpenServiceW(manager.h,service_name,SERVICE_QUERY_STATUS)};if(existing.h){std::fwprintf(stderr,L"Service already exists.\n");return 1;}
    reg prior;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&prior.h)==ERROR_SUCCESS){std::fwprintf(stderr,L"Ohno registry key already exists.\n");return 1;}
    std::wstring dir=directory();if(dir.empty()||!CreateDirectoryW(dir.c_str(),nullptr)){std::fwprintf(stderr,L"Cannot create program directory (%lu)\n",GetLastError());return 1;}
    std::wstring exe=dir+L"\\ohno-service.exe",helper=dir+L"\\ohno-request.exe",tun=dir+L"\\ohno-tun.exe",gpl=dir+L"\\sing-box-LICENSE.txt",wintun=dir+L"\\wintun-LICENSE.txt",shortcut;bool made_key=false;bool made_service=false;int result=1;
    do{
        if(!embedded_exe(exe,101)||!embedded_exe(helper,102)||!embedded_exe(tun,103)||!embedded_exe(gpl,105)||!embedded_exe(wintun,106)){std::fwprintf(stderr,L"Cannot extract service (%lu)\n",GetLastError());break;}
        reg config;DWORD disposition=0;
        if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,nullptr,0,KEY_WRITE,nullptr,&config.h,&disposition)!=ERROR_SUCCESS||disposition!=REG_CREATED_NEW_KEY){std::fwprintf(stderr,L"Cannot create configuration.\n");break;}
        made_key=true;
        if(RegSetValueExW(config.h,L"ServerUrl",0,REG_SZ,reinterpret_cast<const BYTE*>(url),static_cast<DWORD>((wcslen(url)+1)*sizeof(wchar_t)))!=ERROR_SUCCESS){std::fwprintf(stderr,L"Cannot write configuration.\n");break;}
        if(!make_shortcut(helper,shortcut)){std::fwprintf(stderr,L"Cannot create request shortcut.\n");break;}
        if(!shortcut.empty()&&RegSetValueExW(config.h,L"Shortcut",0,REG_SZ,reinterpret_cast<const BYTE*>(shortcut.c_str()),static_cast<DWORD>((shortcut.size()+1)*sizeof(wchar_t)))!=ERROR_SUCCESS){std::fwprintf(stderr,L"Cannot record request shortcut.\n");break;}
        if(certificate_path&&!import_root_certificate(certificate_path,config.h)){std::fwprintf(stderr,L"Cannot import self-signed teacher certificate (%lu)\n",GetLastError());break;}
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
    if(result){if(made_service){sc svc{OpenServiceW(manager.h,service_name,DELETE)};if(svc.h)DeleteService(svc.h);}if(made_key){reg cfg;bool ok=true;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&cfg.h)==ERROR_SUCCESS)ok=remove_imported_certificate(cfg.h);if(ok)RegDeleteTreeW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno");else std::fwprintf(stderr,L"Certificate cleanup failed; registry record retained.\n");}remove_shortcut(shortcut,helper);DeleteFileW(wintun.c_str());DeleteFileW(gpl.c_str());DeleteFileW(tun.c_str());DeleteFileW(helper.c_str());DeleteFileW(exe.c_str());RemoveDirectoryW(dir.c_str());}
    return result;
}
int remove(){
    sc manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT)};if(!manager.h)return 1;
    sc svc{OpenServiceW(manager.h,service_name,SERVICE_STOP|SERVICE_QUERY_STATUS|DELETE)};if(!svc.h){std::fwprintf(stderr,L"Service not found (%lu)\n",GetLastError());return 1;}
    SERVICE_STATUS status{};ControlService(svc.h,SERVICE_CONTROL_STOP,&status);
    for(int i=0;i<40;++i){if(!QueryServiceStatus(svc.h,&status))return 1;if(status.dwCurrentState==SERVICE_STOPPED)break;Sleep(500);}
    if(status.dwCurrentState!=SERVICE_STOPPED){std::fwprintf(stderr,L"Service did not stop; no files removed.\n");return 1;}
    if(!clear_edge_policy()||!clear_edge_allow_policy()){std::fwprintf(stderr,L"Could not restore Edge URL policy; service retained.\n");return 1;}
    reg cfg;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&cfg.h)==ERROR_SUCCESS&&!remove_imported_certificate(cfg.h)){std::fwprintf(stderr,L"Could not remove imported teacher certificate; service retained.\n");return 1;}
    std::wstring shortcut=cfg.h?read_config_string(cfg.h,L"Shortcut"):L"";
    if(!DeleteService(svc.h)){std::fwprintf(stderr,L"Cannot delete service (%lu)\n",GetLastError());return 1;}
    std::wstring dir=directory();std::wstring exe=dir+L"\\ohno-service.exe",helper=dir+L"\\ohno-request.exe";
    remove_shortcut(shortcut,helper);
    DeleteFileW((dir+L"\\ohno-tun.json").c_str());DeleteFileW((dir+L"\\ohno-tun.json.tmp").c_str());
    DeleteFileW((dir+L"\\wintun-LICENSE.txt").c_str());DeleteFileW((dir+L"\\sing-box-LICENSE.txt").c_str());
    DeleteFileW((dir+L"\\ohno-tun.exe").c_str());
    if(!DeleteFileW(helper.c_str()))std::fwprintf(stderr,L"Could not remove request helper (%lu).\n",GetLastError());
    if(!DeleteFileW(exe.c_str()))std::fwprintf(stderr,L"Could not remove service executable (%lu); remove manually after reboot.\n",GetLastError());
    if(!RemoveDirectoryW(dir.c_str()))std::fwprintf(stderr,L"Could not remove program folder (%lu); inspect manually.\n",GetLastError());
    if(RegDeleteTreeW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno")!=ERROR_SUCCESS)std::fwprintf(stderr,L"Could not remove registry settings; inspect manually.\n");
    return 0;
}
}
int wmain(int argc,wchar_t** argv){
    if(argc==3&&std::wcscmp(argv[1],L"--install")==0)return install(argv[2],nullptr);
    if(argc==5&&std::wcscmp(argv[1],L"--install")==0&&std::wcscmp(argv[3],L"--certificate")==0)return install(argv[2],argv[4]);
    if(argc==2&&std::wcscmp(argv[1],L"--remove")==0)return remove();
    std::fwprintf(stderr,L"Usage: ohno-setup.exe --install https://teacher:8443 [--certificate cert.pem] | --remove\n");return 2;
}
