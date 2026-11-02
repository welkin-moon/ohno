#pragma once
#include <string>
namespace ohno {
using SetupCallback = int (*)(const wchar_t* url, const wchar_t* certificate);
int show_install_wizard(SetupCallback install);
bool prompt_maintenance_password(const std::wstring& server,bool uninstall,std::wstring& output);
}
