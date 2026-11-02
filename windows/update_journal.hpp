#pragma once
#include "../src/update_transaction.hpp"
#include <memory>

namespace ohno {
// Requires an already-created, trusted local NTFS installation directory whose
// ACL allows writes only to the service/OS administrators. Does not change ACLs,
// install a service or touch the registry. Rejects reparse points/hardlinks.
class WindowsUpdateJournal final : public UpdateJournalStorage {
    struct Impl;
    std::unique_ptr<Impl> impl;
public:
    explicit WindowsUpdateJournal(const std::wstring& directory);
    ~WindowsUpdateJournal();
    WindowsUpdateJournal(const WindowsUpdateJournal&) = delete;
    WindowsUpdateJournal& operator=(const WindowsUpdateJournal&) = delete;
    const std::wstring& directory_path() const;
    std::string read() override;
    JournalWrite replace(const std::string& document) override;
    // Explicit initial installation only. Never reconstructs a missing/corrupt
    // journal on service startup and never overwrites existing trusted state.
    JournalWrite initialize(const UpdateJournal& initial);
#ifdef OHNO_UPDATE_IO_TESTING
    using FaultHook = void(*)(unsigned);
    static void set_test_fault_hook(FaultHook hook);
#endif
};
}
