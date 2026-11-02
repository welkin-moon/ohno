#pragma once
#include "update_client.hpp"
namespace ohno {
std::wstring service_directory();
std::string installed_release_key();
// Read only after worker health (existing hardware-bound enrollment has run).
// Does not generate identities, persist secrets or ask for a password.
UpdateConnection installed_update_connection();
}
