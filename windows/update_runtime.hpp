#pragma once
#include <functional>
#include "update_client.hpp"
namespace ohno {
struct UpdateRuntimeOptions {
    DWORD poll_ms=60000,health_timeout_ms=90000,restart_delay_ms=3000;
#ifdef OHNO_UPDATE_IO_TESTING
    void(*checkpoint)(unsigned)=nullptr;
#endif
};
// Existing journal only; missing/corrupt state fails closed, never resets floor.
// Connection is read afresh after worker health so cloned identity has already
// been regenerated. Callback never asks for or retains a teacher password.
void run_update_runtime(const std::wstring& root,const std::string& release_key,HANDLE stop,
    const std::function<UpdateConnection()>& connection,const UpdateRuntimeOptions& options={});
}
