#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include "setup_ui.hpp"
#include "maintenance_http.hpp"
#pragma comment(lib, "gdi32.lib")

namespace {

struct UiFonts {
    HFONT normal = nullptr;
    HFONT bold = nullptr;
    int dpi = 96;

    void init(HWND hwnd) {
        using GetDpiFn = UINT(WINAPI*)(HWND);
        if (auto* user32 = GetModuleHandleW(L"user32.dll")) {
            if (auto fn = reinterpret_cast<GetDpiFn>(GetProcAddress(user32, "GetDpiForWindow"))) {
                UINT d = fn(hwnd);
                if (d >= 72 && d <= 384) dpi = static_cast<int>(d);
            }
        }
        NONCLIENTMETRICSW ncm{};
        ncm.cbSize = sizeof(ncm);
        if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
            LOGFONTW lf = ncm.lfMessageFont;
            lf.lfHeight = -MulDiv(10, dpi, 72);
            normal = CreateFontIndirectW(&lf);
            lf.lfWeight = FW_SEMIBOLD;
            lf.lfHeight = -MulDiv(12, dpi, 72);
            bold = CreateFontIndirectW(&lf);
        }
        if (!normal) normal = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        if (!bold) bold = normal;
    }

    int px(int logical) const { return MulDiv(logical, dpi, 96); }

    ~UiFonts() {
        HFONT def = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        if (bold && bold != normal && bold != def) DeleteObject(bold);
        if (normal && normal != def) DeleteObject(normal);
    }
};

void apply_font(HWND ctrl, HFONT font) {
    if (ctrl && font) SendMessageW(ctrl, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

std::wstring read_edit(HWND ctrl) {
    int length = GetWindowTextLengthW(ctrl);
    if (length <= 0 || length > 2048) return {};
    std::vector<wchar_t> data(static_cast<std::size_t>(length) + 1, 0);
    GetWindowTextW(ctrl, data.data(), static_cast<int>(data.size()));
    return std::wstring(data.data());
}

void center_window(HWND hwnd) {
    RECT rc{};
    if (!GetWindowRect(hwnd, &rc)) return;
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(hwnd, nullptr, (sw - w) / 2, (sh - h) / 2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

constexpr int id_url = 101;
constexpr int id_probe = 102;
constexpr int id_status = 103;
constexpr int id_cert = 104;
constexpr int id_browse = 105;
constexpr int id_password = 106;
constexpr int id_install = 107;
constexpr int id_cancel = 108;

struct Wizard {
    HWND window = nullptr;
    HWND url = nullptr;
    HWND probe_btn = nullptr;
    HWND status = nullptr;
    HWND cert = nullptr;
    HWND browse_btn = nullptr;
    HWND password = nullptr;
    HWND install_btn = nullptr;
    UiFonts fonts;
    ohno::WizardInstallCallback action = nullptr;
    ohno::TeacherBootstrapInfo probed;
    bool has_probed = false;
    int result = 2;
};

void set_status(Wizard* w, const std::wstring& text) {
    SetWindowTextW(w->status, text.c_str());
}

void do_probe(Wizard* w) {
    const auto raw_url = read_edit(w->url);
    const auto normalized = ohno::normalize_teacher_origin(raw_url);
    if (normalized.empty()) {
        w->has_probed = false;
        set_status(w, L"地址格式无效。请填写教师机局域网 IP（如 10.181.203.70）或域名。");
        return;
    }
    SetWindowTextW(w->url, normalized.c_str());
    set_status(w, L"正在连接教师端并核验证书，请稍候…");
    UpdateWindow(w->window);
    EnableWindow(w->probe_btn, FALSE);
    EnableWindow(w->install_btn, FALSE);
    w->probed = ohno::probe_teacher_bootstrap(normalized);
    EnableWindow(w->probe_btn, TRUE);
    EnableWindow(w->install_btn, TRUE);

    switch (w->probed.status) {
    case ohno::ProbeResult::Ok: {
        w->has_probed = true;
        SetWindowTextW(w->cert, L"（已在线获取教师端公开证书，无需本地文件）");
        std::wstring msg = L"已连接教师端！证书指纹：" + w->probed.fingerprint + L"\r\n";
        if (!w->probed.maintenance_configured) {
            msg += L"注意：教师端尚未设置维护密码，请先在教师端页面设置 12 位以上维护密码。";
        } else {
            msg += L"请核对指纹与教师端页面一致，在下方输入维护密码后点击「安装」。";
        }
        set_status(w, msg);
        SetFocus(w->password);
        break;
    }
    case ohno::ProbeResult::CertHostMismatch:
        w->has_probed = false;
        set_status(w, L"连接失败：教师端证书未包含当前 IP 或域名。\r\n请在教师端管理页点击「重新签发含当前局域网 IP 的证书」后重试。");
        break;
    case ohno::ProbeResult::CertExpired:
        w->has_probed = false;
        set_status(w, L"连接失败：教师端证书已过期或尚未生效，请检查本机与教师机系统时间。");
        break;
    case ohno::ProbeResult::InvalidServer:
        w->has_probed = false;
        set_status(w, L"地址格式无效。示例：10.181.203.70 或 https://teacher-pc:8443");
        break;
    default:
        w->has_probed = false;
        set_status(w, L"无法连接到 " + normalized + L"。\r\n请确认教师端已运行、两台电脑在同一局域网，且教师机防火墙已放行 TCP 8443 端口。");
        break;
    }
}

LRESULT CALLBACK wizard_proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    Wizard* w = reinterpret_cast<Wizard*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        w = reinterpret_cast<Wizard*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(w));
        return TRUE;
    }
    if (message == WM_CREATE && w) {
        w->window = hwnd;
        w->fonts.init(hwnd);
        auto S = [&](int v) { return w->fonts.px(v); };

        auto add_label = [&](const wchar_t* text, int x, int y, int width, int height, HFONT font) {
            HWND h = CreateWindowW(L"STATIC", text, WS_VISIBLE | WS_CHILD, S(x), S(y), S(width), S(height), hwnd, nullptr, nullptr, nullptr);
            apply_font(h, font);
            return h;
        };

        add_label(L"安装 Ohno 课堂助手", 22, 16, 480, 26, w->fonts.bold);
        add_label(L"只需输入教师机 IP（如 10.181.203.70），点击「连接教师端」即可自动获取证书。", 22, 44, 520, 20, w->fonts.normal);

        add_label(L"1. 教师机地址（IP 或域名，默认端口 8443）", 22, 74, 420, 20, w->fonts.normal);
        w->url = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
            S(22), S(98), S(395), S(28), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id_url)), nullptr, nullptr);
        apply_font(w->url, w->fonts.normal);
        w->probe_btn = CreateWindowW(L"BUTTON", L"连接教师端",
            WS_VISIBLE | WS_CHILD | WS_TABSTOP,
            S(427), S(97), S(115), S(30), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id_probe)), nullptr, nullptr);
        apply_font(w->probe_btn, w->fonts.normal);

        w->status = CreateWindowExW(WS_EX_STATICEDGE, L"STATIC",
            L"提示：您也可以直接在教师端网页下载「Ohno-School-Setup.exe」一键安装，无需填写地址。",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            S(22), S(138), S(520), S(52), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id_status)), nullptr, nullptr);
        apply_font(w->status, w->fonts.normal);

        add_label(L"2. 教师维护密码（在教师端页面设置，12–128 字符，不是课堂 PIN）", 22, 202, 520, 20, w->fonts.normal);
        w->password = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            S(22), S(226), S(520), S(28), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id_password)), nullptr, nullptr);
        apply_font(w->password, w->fonts.normal);
        SendMessageW(w->password, EM_SETLIMITTEXT, 256, 0);

        add_label(L"可选：离线证书文件（自动连接成功后无需填写）", 22, 266, 420, 20, w->fonts.normal);
        w->cert = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
            S(22), S(290), S(415), S(28), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id_cert)), nullptr, nullptr);
        apply_font(w->cert, w->fonts.normal);
        w->browse_btn = CreateWindowW(L"BUTTON", L"浏览…",
            WS_VISIBLE | WS_CHILD | WS_TABSTOP,
            S(447), S(289), S(95), S(30), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id_browse)), nullptr, nullptr);
        apply_font(w->browse_btn, w->fonts.normal);

        w->install_btn = CreateWindowW(L"BUTTON", L"立即安装",
            WS_VISIBLE | WS_CHILD | WS_TABSTOP | BS_DEFPUSHBUTTON,
            S(312), S(338), S(115), S(34), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id_install)), nullptr, nullptr);
        apply_font(w->install_btn, w->fonts.normal);
        HWND cancel_btn = CreateWindowW(L"BUTTON", L"取消",
            WS_VISIBLE | WS_CHILD | WS_TABSTOP,
            S(437), S(338), S(105), S(34), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id_cancel)), nullptr, nullptr);
        apply_font(cancel_btn, w->fonts.normal);

        RECT desired{0, 0, S(566), S(390)};
        AdjustWindowRectEx(&desired, static_cast<DWORD>(GetWindowLongPtrW(hwnd, GWL_STYLE)), FALSE,
                           static_cast<DWORD>(GetWindowLongPtrW(hwnd, GWL_EXSTYLE)));
        SetWindowPos(hwnd, nullptr, 0, 0, desired.right - desired.left, desired.bottom - desired.top, SWP_NOMOVE | SWP_NOZORDER);
        center_window(hwnd);
        SetFocus(w->url);
        return 0;
    }
    if (message == WM_CTLCOLORSTATIC) {
        HDC hdc = reinterpret_cast<HDC>(wp);
        SetBkMode(hdc, TRANSPARENT);
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_BTNFACE));
    }
    if (message == WM_COMMAND && w) {
        const int id = LOWORD(wp);
        if (id == id_probe) {
            do_probe(w);
            return 0;
        }
        if (id == id_browse) {
            wchar_t path[32768]{};
            OPENFILENAMEW dialog{};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = hwnd;
            dialog.lpstrFile = path;
            dialog.nMaxFile = 32768;
            dialog.lpstrFilter = L"证书 (*.pem;*.cer;*.crt)\0*.pem;*.cer;*.crt\0所有文件 (*.*)\0*.*\0";
            dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
            if (GetOpenFileNameW(&dialog)) {
                w->has_probed = false;
                SetWindowTextW(w->cert, path);
                set_status(w, L"已选择本地证书文件。输入教师维护密码后点击「立即安装」。");
            }
            return 0;
        }
        if (id == id_cancel) {
            SetWindowTextW(w->password, L"");
            DestroyWindow(hwnd);
            return 0;
        }
        if (id == id_install) {
            const auto raw_url = read_edit(w->url);
            const auto normalized = ohno::normalize_teacher_origin(raw_url);
            if (normalized.empty()) {
                MessageBoxW(hwnd, L"请填写有效的教师机 IP 或域名（例：10.181.203.70）。", L"Ohno 安装", MB_ICONWARNING | MB_OK);
                SetFocus(w->url);
                return 0;
            }
            SetWindowTextW(w->url, normalized.c_str());

            std::wstring cert_path = read_edit(w->cert);
            const bool using_probed_cert = w->has_probed && w->probed.normalized_server == normalized;
            if (!using_probed_cert && (cert_path.empty() || cert_path.front() == L'（')) {
                // Auto-probe once if user clicked Install directly after typing IP + password!
                do_probe(w);
                if (!w->has_probed || w->probed.status != ohno::ProbeResult::Ok) {
                    return 0;
                }
                const std::wstring confirm = L"已自动获取教师端证书。\r\n\r\n教师端地址：" + normalized +
                    L"\r\n证书指纹：" + w->probed.fingerprint +
                    L"\r\n\r\n请确认该指纹与教师端网页显示一致，是否继续安装？";
                if (MessageBoxW(hwnd, confirm.c_str(), L"核对教师端证书指纹", MB_YESNO | MB_ICONQUESTION) != IDYES) {
                    return 0;
                }
            }

            ohno::WizardInstallParams params;
            params.server_url = normalized;
            if (w->has_probed && w->probed.normalized_server == normalized) {
                params.certificate_pem = w->probed.certificate_pem;
                params.release_public_key = w->probed.release_public_key;
            } else {
                params.certificate_path = cert_path;
            }

            // Read password directly into wiping buffer.
            int pw_len = GetWindowTextLengthW(w->password);
            if (pw_len < 12 || pw_len > 256) {
                MessageBoxW(hwnd, L"请输入教师维护密码（12–128 字符，在教师端网页设置，不是 4–8 位课堂 PIN）。",
                            L"Ohno 安装", MB_ICONWARNING | MB_OK);
                SetFocus(w->password);
                return 0;
            }
            params.password.resize(static_cast<std::size_t>(pw_len) + 1);
            GetWindowTextW(w->password, params.password.data(), pw_len + 1);
            params.password.resize(static_cast<std::size_t>(pw_len));

            EnableWindow(w->install_btn, FALSE);
            EnableWindow(w->probe_btn, FALSE);
            set_status(w, L"正在向教师端验证维护授权并安装服务，请稍候…");
            UpdateWindow(hwnd);

            std::wstring err_msg;
            const int code = w->action(params, err_msg);
            if (!params.password.empty()) {
                SecureZeroMemory(params.password.data(), params.password.size() * sizeof(wchar_t));
                params.password.clear();
            }
            EnableWindow(w->install_btn, TRUE);
            EnableWindow(w->probe_btn, TRUE);

            if (code == 0) {
                SetWindowTextW(w->password, L"");
                w->result = 0;
                MessageBoxW(hwnd, L"安装完成！Ohno 服务已自动启动。\r\n接下来请在教师端网页的「设备」列表中批准这台学生机。",
                            L"Ohno 安装完成", MB_OK | MB_ICONINFORMATION);
                DestroyWindow(hwnd);
            } else if (code != 2) {
                if (err_msg.empty()) {
                    err_msg = L"安装失败，请检查教师维护密码、教师端地址与防火墙 TCP 8443。";
                }
                set_status(w, err_msg);
                MessageBoxW(hwnd, err_msg.c_str(), L"Ohno 安装失败", MB_OK | MB_ICONERROR);
            }
            return 0;
        }
    }
    if (message == WM_CLOSE) {
        if (w && w->password) SetWindowTextW(w->password, L"");
        DestroyWindow(hwnd);
        return 0;
    }
    if (message == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, message, wp, lp);
}

struct PasswordPrompt {
    HWND window = nullptr;
    HWND edit = nullptr;
    UiFonts fonts;
    const std::wstring* server = nullptr;
    std::wstring* output = nullptr;
    bool accepted = false;
    bool uninstall = false;
};

LRESULT CALLBACK password_message(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    auto* state = reinterpret_cast<PasswordPrompt*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        state = static_cast<PasswordPrompt*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        return TRUE;
    }
    if (message == WM_CREATE && state) {
        state->window = hwnd;
        state->fonts.init(hwnd);
        auto S = [&](int v) { return state->fonts.px(v); };

        auto add_label = [&](const wchar_t* text, int x, int y, int width, int height, HFONT font) {
            HWND h = CreateWindowW(L"STATIC", text, WS_VISIBLE | WS_CHILD, S(x), S(y), S(width), S(height), hwnd, nullptr, nullptr, nullptr);
            apply_font(h, font);
        };

        add_label(state->uninstall ? L"卸载需要教师维护密码（不是课堂 PIN）" : L"安装需要教师维护密码（不是课堂 PIN）",
                  20, 16, 520, 24, state->fonts.bold);
        HWND srv_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", state->server->c_str(),
            WS_VISIBLE | WS_CHILD | ES_READONLY | ES_AUTOHSCROLL,
            S(20), S(48), S(520), S(26), hwnd, nullptr, nullptr, nullptr);
        apply_font(srv_edit, state->fonts.normal);
        add_label(L"维护密码仅在线发送至上方教师端验证，不会保存到本机或系统镜像。", 20, 84, 520, 20, state->fonts.normal);
        state->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            S(20), S(112), S(520), S(28), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(201)), nullptr, nullptr);
        apply_font(state->edit, state->fonts.normal);
        SendMessageW(state->edit, EM_SETLIMITTEXT, 256, 0);

        HWND ok_btn = CreateWindowW(L"BUTTON", L"确认", WS_VISIBLE | WS_CHILD | WS_TABSTOP | BS_DEFPUSHBUTTON,
            S(318), S(156), S(106), S(32), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDOK)), nullptr, nullptr);
        apply_font(ok_btn, state->fonts.normal);
        HWND cancel_btn = CreateWindowW(L"BUTTON", L"取消", WS_VISIBLE | WS_CHILD | WS_TABSTOP,
            S(434), S(156), S(106), S(32), hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)), nullptr, nullptr);
        apply_font(cancel_btn, state->fonts.normal);

        RECT desired{0, 0, S(560), S(206)};
        AdjustWindowRectEx(&desired, static_cast<DWORD>(GetWindowLongPtrW(hwnd, GWL_STYLE)), FALSE,
                           static_cast<DWORD>(GetWindowLongPtrW(hwnd, GWL_EXSTYLE)));
        SetWindowPos(hwnd, nullptr, 0, 0, desired.right - desired.left, desired.bottom - desired.top, SWP_NOMOVE | SWP_NOZORDER);
        center_window(hwnd);
        SetFocus(state->edit);
        return 0;
    }
    if (message == WM_CTLCOLORSTATIC) {
        HDC hdc = reinterpret_cast<HDC>(wp);
        SetBkMode(hdc, TRANSPARENT);
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_BTNFACE));
    }
    if (message == WM_COMMAND && state) {
        if (LOWORD(wp) == IDOK) {
            const int length = GetWindowTextLengthW(state->edit);
            if (length <= 0 || length > 256) {
                SetFocus(state->edit);
                return 0;
            }
            state->output->resize(static_cast<std::size_t>(length) + 1);
            const int copied = GetWindowTextW(state->edit, state->output->data(), length + 1);
            if (copied != length) {
                SecureZeroMemory(state->output->data(), state->output->size() * sizeof(wchar_t));
                state->output->clear();
                SetFocus(state->edit);
                return 0;
            }
            state->output->resize(static_cast<std::size_t>(length));
            SetWindowTextW(state->edit, L"");
            state->accepted = true;
            DestroyWindow(hwnd);
            return 0;
        }
        if (LOWORD(wp) == IDCANCEL) {
            SetWindowTextW(state->edit, L"");
            DestroyWindow(hwnd);
            return 0;
        }
    }
    if (message == WM_CLOSE) {
        if (state && state->edit) SetWindowTextW(state->edit, L"");
        DestroyWindow(hwnd);
        return 0;
    }
    if (message == WM_DESTROY) return 0;
    return DefWindowProcW(hwnd, message, wp, lp);
}

} // namespace

namespace ohno {

int show_install_wizard(WizardInstallCallback install) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = wizard_proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"OhnoSetupWindowV2";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);
    if (!RegisterClassW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return 1;
    Wizard state;
    state.action = install;
    HWND window = CreateWindowExW(0, wc.lpszClassName, L"Ohno 课堂助手 - 安装向导",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 580, 420, nullptr, nullptr, wc.hInstance, &state);
    if (!window) return 1;
    ShowWindow(window, SW_SHOWNORMAL);
    UpdateWindow(window);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    return state.result;
}

bool prompt_maintenance_password(const std::wstring& server, bool uninstall, std::wstring& output) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = password_message;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"OhnoMaintenancePasswordV1";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);
    if (!RegisterClassW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
    PasswordPrompt state;
    state.server = &server;
    state.output = &output;
    state.uninstall = uninstall;
    HWND owner = GetActiveWindow();
    HWND window = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"Ohno - 教师维护授权",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 580, 240, owner, nullptr, wc.hInstance, &state);
    if (!window) return false;
    if (owner) EnableWindow(owner, FALSE);
    ShowWindow(window, SW_SHOWNORMAL);
    UpdateWindow(window);
    SetFocus(state.edit);
    MSG message{};
    bool quit = false;
    while (IsWindow(window)) {
        const auto result = GetMessageW(&message, nullptr, 0, 0);
        if (result <= 0) {
            quit = result == 0;
            DestroyWindow(window);
            break;
        }
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    if (owner) {
        EnableWindow(owner, TRUE);
        SetActiveWindow(owner);
    }
    if (quit) PostQuitMessage(static_cast<int>(message.wParam));
    return state.accepted;
}

} // namespace ohno
