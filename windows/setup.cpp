// Experimental standalone setup; not yet suitable for deployment.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <winhttp.h>
#include <cstdio>
#include <cwchar>
#include <string>
#include "browser_policy.hpp"
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"winhttp.lib")
namespace {
constexpr wchar_t service_name[]=L"OhnoPrototype";
struct sc {SC_HANDLE h=nullptr;~sc(){if(h)CloseServiceHandle(h);}};
struct reg {HKEY h=nullptr;~reg(){if(h)RegCloseKey(h);}};
std::wstring directory(){PWSTR raw=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,0,nullptr,&raw)))return {};std::wstring p=raw;CoTaskMemFree(raw);return p+L"\\OhnoPrototype";}
bool valid_url(const wchar_t* url){URL_COMPONENTSW c{};c.dwStructSize=sizeof(c);c.dwHostNameLength=DWORD(-1);c.dwUserNameLength=DWORD(-1);c.dwPasswordLength=DWORD(-1);c.dwUrlPathLength=DWORD(-1);c.dwExtraInfoLength=DWORD(-1);return WinHttpCrackUrl(url,0,0,&c)&&c.nScheme==INTERNET_SCHEME_HTTPS&&c.dwHostNameLength&&!c.dwUserNameLength&&!c.dwPasswordLength&&!c.dwExtraInfoLength&&c.dwUrlPathLength<=1;}
bool embedded_exe(const std::wstring& path){
    HRSRC res=FindResourceW(nullptr,MAKEINTRESOURCEW(101),RT_RCDATA);if(!res)return false;
    HGLOBAL data=LoadResource(nullptr,res);DWORD size=SizeofResource(nullptr,res);void* src=LockResource(data);if(!src||!size)return false;
    HANDLE f=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(f==INVALID_HANDLE_VALUE)return false;
    DWORD wrote=0;BOOL ok=WriteFile(f,src,size,&wrote,nullptr);CloseHandle(f);return ok&&wrote==size;
}
int install(const wchar_t* url){
    if(!valid_url(url)){std::fwprintf(stderr,L"Expected an HTTPS origin, e.g. https://teacher.example:8443\n");return 2;}
    sc manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE)};if(!manager.h){std::fwprintf(stderr,L"Administrator access required (%lu)\n",GetLastError());return 1;}
    sc existing{OpenServiceW(manager.h,service_name,SERVICE_QUERY_STATUS)};if(existing.h){std::fwprintf(stderr,L"Service already exists.\n");return 1;}
    reg prior;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&prior.h)==ERROR_SUCCESS){std::fwprintf(stderr,L"Ohno registry key already exists.\n");return 1;}
    std::wstring dir=directory();if(dir.empty()||!CreateDirectoryW(dir.c_str(),nullptr)){std::fwprintf(stderr,L"Cannot create program directory (%lu)\n",GetLastError());return 1;}
    std::wstring exe=dir+L"\\ohno-service.exe";bool made_key=false;bool made_service=false;int result=1;
    do{
        if(!embedded_exe(exe)){std::fwprintf(stderr,L"Cannot extract service (%lu)\n",GetLastError());break;}
        reg config;DWORD disposition=0;
        if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,nullptr,0,KEY_WRITE,nullptr,&config.h,&disposition)!=ERROR_SUCCESS||disposition!=REG_CREATED_NEW_KEY){std::fwprintf(stderr,L"Cannot create configuration.\n");break;}
        made_key=true;
        if(RegSetValueExW(config.h,L"ServerUrl",0,REG_SZ,reinterpret_cast<const BYTE*>(url),static_cast<DWORD>((wcslen(url)+1)*sizeof(wchar_t)))!=ERROR_SUCCESS){std::fwprintf(stderr,L"Cannot write configuration.\n");break;}
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
    if(result){if(made_service){sc svc{OpenServiceW(manager.h,service_name,DELETE)};if(svc.h)DeleteService(svc.h);}if(made_key)RegDeleteTreeW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno");DeleteFileW(exe.c_str());RemoveDirectoryW(dir.c_str());}
    return result;
}
int remove(){
    sc manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT)};if(!manager.h)return 1;
    sc svc{OpenServiceW(manager.h,service_name,SERVICE_STOP|SERVICE_QUERY_STATUS|DELETE)};if(!svc.h){std::fwprintf(stderr,L"Service not found (%lu)\n",GetLastError());return 1;}
    SERVICE_STATUS status{};ControlService(svc.h,SERVICE_CONTROL_STOP,&status);
    for(int i=0;i<40;++i){if(!QueryServiceStatus(svc.h,&status))return 1;if(status.dwCurrentState==SERVICE_STOPPED)break;Sleep(500);}
    if(status.dwCurrentState!=SERVICE_STOPPED){std::fwprintf(stderr,L"Service did not stop; no files removed.\n");return 1;}
    if(!clear_edge_policy()){std::fwprintf(stderr,L"Could not restore Edge URL policy; service retained.\n");return 1;}
    if(!DeleteService(svc.h)){std::fwprintf(stderr,L"Cannot delete service (%lu)\n",GetLastError());return 1;}
    std::wstring dir=directory();std::wstring exe=dir+L"\\ohno-service.exe";
    if(!DeleteFileW(exe.c_str()))std::fwprintf(stderr,L"Could not remove service executable (%lu); remove manually after reboot.\n",GetLastError());
    if(!RemoveDirectoryW(dir.c_str()))std::fwprintf(stderr,L"Could not remove program folder (%lu); inspect manually.\n",GetLastError());
    if(RegDeleteTreeW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno")!=ERROR_SUCCESS)std::fwprintf(stderr,L"Could not remove registry settings; inspect manually.\n");
    return 0;
}
}
int wmain(int argc,wchar_t** argv){
    if(argc==3&&std::wcscmp(argv[1],L"--install")==0)return install(argv[2]);
    if(argc==2&&std::wcscmp(argv[1],L"--remove")==0)return remove();
    std::fwprintf(stderr,L"Usage: ohno-setup.exe --install https://teacher:8443 | --remove\n");return 2;
}
