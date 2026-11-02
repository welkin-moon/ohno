#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "update_journal.hpp"
#include "../src/update_package.hpp"

namespace ohno {
constexpr std::uint64_t updater_protocol_version=1;
#ifdef OHNO_UPDATE_IO_TESTING
void set_payload_test_fault_hook(void(*hook)(unsigned));
#endif
std::wstring payload_directory(const WindowsUpdateJournal& storage,const UpdateRevision& revision);
// Verifies outer signature/freshness/sequence BEFORE opening package. Full size,
// SHA256, fixed layout, x64 and version precede ANY extraction. Storage owns the
// installation lock and pins trusted ancestors; this never changes selector.
UpdateRevision stage_update_payload(WindowsUpdateJournal& storage,const std::string& offer,
    const std::string& pinned_key,const std::wstring& package_file,std::uint64_t high_water,
    std::uint64_t now,HANDLE stop_event=nullptr);
// Initial trusted installer resources only, after normal teacher authorization.
UpdateRevision stage_initial_payload(WindowsUpdateJournal& storage,std::string_view package,HANDLE stop_event=nullptr);
// Revalidates already-installed bytes against journal identity and (for seq>0)
// installed school key. Expiry is not reapplied to a previously committed build.
// Does not authorize new updates or execute anything.
// Read-only launcher variant pins the trusted root without taking writer lock.
void verify_staged_payload(const std::wstring& trusted_root,const UpdateRevision& revision,
    const std::string& pinned_key,HANDLE stop_event=nullptr);
void verify_staged_payload(WindowsUpdateJournal& storage,const UpdateRevision& revision,
    const std::string& pinned_key,HANDLE stop_event=nullptr);
}
