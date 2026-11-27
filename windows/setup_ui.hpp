#pragma once
#include <string>

namespace ohno {

struct WizardInstallParams {
    std::wstring server_url;       // normalized https://<host>:<port>
    std::wstring certificate_path; // optional local .pem path
    std::string certificate_pem;   // populated when probed online
    std::string release_public_key;// optional release public key from bootstrap
    std::wstring password;         // maintenance password entered in same window
};

// Returns 0 on success, 2 on user cancel, 1 on failure (with human-readable Chinese message in error_out).
using WizardInstallCallback = int (*)(const WizardInstallParams& params, std::wstring& error_out);

int show_install_wizard(WizardInstallCallback install);
bool prompt_maintenance_password(const std::wstring& server, bool uninstall, std::wstring& output);

}
