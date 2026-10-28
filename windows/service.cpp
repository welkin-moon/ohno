// Windows service lifecycle scaffold. No network enforcement is implemented.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include "agent.hpp"
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
        report(SERVICE_STOP_PENDING, NO_ERROR, 3000);
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
    run_agent(stop_event);
    CloseHandle(stop_event);
    stop_event = nullptr;
    report(SERVICE_STOPPED);
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
