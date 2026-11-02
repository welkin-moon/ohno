// Standard SCM host. Managed payload layout is explicit; no silent migration.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cwchar>
#include "agent.hpp"
#include "update_runtime.hpp"
#include "update_configuration.hpp"
namespace {
constexpr wchar_t service_name[] = L"OhnoPrototype";
SERVICE_STATUS_HANDLE status_handle = nullptr;
SERVICE_STATUS status_info{};
HANDLE stop_event = nullptr;
void report(DWORD state, DWORD code = NO_ERROR, DWORD hint = 0) {
    status_info.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status_info.dwCurrentState = state;
    status_info.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    status_info.dwWin32ExitCode = code;
    status_info.dwServiceSpecificExitCode = 0;
    status_info.dwCheckPoint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 1 : 0;
    status_info.dwWaitHint = hint;
    if (status_handle) SetServiceStatus(status_handle, &status_info);
}
DWORD WINAPI control(DWORD command, DWORD, LPVOID, LPVOID) {
    if (command == SERVICE_CONTROL_STOP || command == SERVICE_CONTROL_SHUTDOWN) {
        report(SERVICE_STOP_PENDING, NO_ERROR, 15000);
        if (stop_event) SetEvent(stop_event);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}
void WINAPI service_main(DWORD, LPWSTR*) {
    status_handle = RegisterServiceCtrlHandlerExW(service_name, control, nullptr);
    if (!status_handle) return;
    report(SERVICE_START_PENDING, NO_ERROR, 3000);
    stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop_event) { report(SERVICE_STOPPED, GetLastError()); return; }
    report(SERVICE_RUNNING);
    DWORD result=NO_ERROR;
    try {
        HKEY config=nullptr;DWORD layout=0,size=sizeof(layout),type=0;
        if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Ohno",0,KEY_READ,&config)==ERROR_SUCCESS){
            const auto queried=RegQueryValueExW(config,L"PayloadLayout",nullptr,&type,reinterpret_cast<BYTE*>(&layout),&size);
            RegCloseKey(config);
            if(queried==ERROR_FILE_NOT_FOUND)layout=0;
            else if(queried!=ERROR_SUCCESS||type!=REG_DWORD||size!=sizeof(layout))throw std::runtime_error("corrupt installation layout");
        }
        if(layout==1)ohno::run_update_runtime(ohno::service_directory(),ohno::installed_release_key(),stop_event,ohno::installed_update_connection);
        else if(layout==0)run_agent(stop_event); // existing installation, no automatic trust/layout upgrade
        else throw std::runtime_error("unsupported installation layout");
    }catch(...){OutputDebugStringW(L"ohno: worker/update host failed; standard service recovery remains available\n");result=ERROR_SERVICE_SPECIFIC_ERROR;}
    CloseHandle(stop_event);
    stop_event = nullptr;
    report(SERVICE_STOPPED,result);
}
}
int wmain() {
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(service_name), service_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        std::fwprintf(stderr, L"Start the prototype through the Windows service manager. Error %lu\n", GetLastError());
        return 1;
    }
    return 0;
}
