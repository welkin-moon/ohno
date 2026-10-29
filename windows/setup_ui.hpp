#pragma once
namespace ohno {
using SetupCallback = int (*)(const wchar_t* url, const wchar_t* certificate);
int show_install_wizard(SetupCallback install);
}
