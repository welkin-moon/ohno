#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <memory>
#include "update_payload.hpp"
#include "../src/update_health.hpp"
namespace ohno {
#ifdef OHNO_UPDATE_IO_TESTING
void set_worker_test_hooks(void(*hook)(unsigned,DWORD),bool fail_drain=false);
#endif
// One child process tree, owned by a kill-on-close job. Only its stop event and
// health pipe writer are inherited. No shell, shared named health pipe or secret
// command-line arguments. A normal host stop terminates ownership, not restarts.
class WorkerProcess {
    struct Impl;std::unique_ptr<Impl> impl;
public:
    WorkerProcess(WindowsUpdateJournal& storage,const UpdateRevision& revision,
        const std::string& pinned_key,const std::string& transaction,HANDLE host_stop,ULONGLONG not_after=0);
    ~WorkerProcess();
    WorkerProcess(const WorkerProcess&)=delete;
    WorkerProcess& operator=(const WorkerProcess&)=delete;
    bool healthy(HANDLE host_stop,DWORD timeout_ms,UpdateHealth& proof);
    bool running() const;
    // True only after the entire owned job has no active processes.
    bool stop() noexcept;
};
}
