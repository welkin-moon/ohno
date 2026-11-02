#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include "setup_ui.hpp"

namespace {
constexpr int url_field=101,cert_field=102,browse_button=103,install_button=104;
struct Wizard {
    HWND window=nullptr,url=nullptr,cert=nullptr,button=nullptr;
    ohno::SetupCallback action=nullptr;
    int result=2;
};
void caption(HWND parent,const wchar_t* text,int x,int y,int width=430){
    CreateWindowW(L"STATIC",text,WS_VISIBLE|WS_CHILD,x,y,width,30,parent,nullptr,nullptr,nullptr);
}
std::wstring field(HWND window){
    int length=GetWindowTextLengthW(window);
    if(length<0||length>2048)return {};
    std::vector<wchar_t> data(static_cast<std::size_t>(length)+1,0);
    GetWindowTextW(window,data.data(),static_cast<int>(data.size()));
    return std::wstring(data.data());
}
LRESULT CALLBACK on_message(HWND hwnd,UINT message,WPARAM wp,LPARAM lp){
    Wizard* wizard=reinterpret_cast<Wizard*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA));
    if(message==WM_NCCREATE){
        auto* cs=reinterpret_cast<CREATESTRUCTW*>(lp);
        wizard=reinterpret_cast<Wizard*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(wizard));
        return TRUE;
    }
    if(message==WM_CREATE&&wizard){
        wizard->window=hwnd;
        caption(hwnd,L"Ohno 课堂助手 - 安装到这台电脑",18,14);
        caption(hwnd,L"教师端 HTTPS 地址（例：https://teacher-pc:8443）",18,48);
        wizard->url=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"https://ohno-teacher:8443",
            WS_VISIBLE|WS_CHILD|WS_TABSTOP|ES_AUTOHSCROLL,18,78,440,27,
            hwnd,reinterpret_cast<HMENU>(static_cast<INT_PTR>(url_field)),nullptr,nullptr);
        caption(hwnd,L"教师端证书（自签名 HTTPS 时需要，学校 IT 提供）",18,117);
        wizard->cert=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",
            WS_VISIBLE|WS_CHILD|WS_TABSTOP|ES_AUTOHSCROLL,18,148,338,27,
            hwnd,reinterpret_cast<HMENU>(static_cast<INT_PTR>(cert_field)),nullptr,nullptr);
        CreateWindowW(L"BUTTON",L"浏览…",WS_VISIBLE|WS_CHILD|WS_TABSTOP,
            367,147,91,29,hwnd,reinterpret_cast<HMENU>(static_cast<INT_PTR>(browse_button)),nullptr,nullptr);
        wizard->button=CreateWindowW(L"BUTTON",L"安装",WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_DEFPUSHBUTTON,
            348,202,110,34,hwnd,reinterpret_cast<HMENU>(static_cast<INT_PTR>(install_button)),nullptr,nullptr);
        caption(hwnd,L"安装后自动启动服务；电脑需经教师批准。",18,207,315);
        return 0;
    }
    if(message==WM_COMMAND&&wizard){
        if(LOWORD(wp)==browse_button){
            wchar_t path[32768]{};
            OPENFILENAMEW dialog{};dialog.lStructSize=sizeof(dialog);dialog.hwndOwner=hwnd;
            dialog.lpstrFile=path;dialog.nMaxFile=32768;
            dialog.lpstrFilter=L"证书 (*.pem;*.cer;*.crt)\0*.pem;*.cer;*.crt\0所有文件 (*.*)\0*.*\0";
            dialog.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;
            if(GetOpenFileNameW(&dialog))SetWindowTextW(wizard->cert,path);
            return 0;
        }
        if(LOWORD(wp)==install_button){
            const auto url=field(wizard->url),cert=field(wizard->cert);
            if(url.empty()){
                MessageBoxW(hwnd,L"请填写教师端 HTTPS 地址。",L"Ohno",MB_ICONWARNING|MB_OK);return 0;
            }
            EnableWindow(wizard->button,FALSE);
            const int result=wizard->action(url.c_str(),cert.empty()?nullptr:cert.c_str());
            EnableWindow(wizard->button,TRUE);
            if(result==0){
                wizard->result=0;
                MessageBoxW(hwnd,L"安装完成。Ohno 服务已启动，接下来由教师端批准这台设备。",
                    L"Ohno",MB_OK|MB_ICONINFORMATION);
                DestroyWindow(hwnd);
            }else if(result!=2){
                MessageBoxW(hwnd,L"安装未完成，请检查教师维护密码、教师端地址、证书和服务状态。此测试版会回滚已创建的安装文件。",
                    L"Ohno",MB_OK|MB_ICONERROR);
            }
            return 0;
        }
    }
    if(message==WM_CLOSE){DestroyWindow(hwnd);return 0;}
    if(message==WM_DESTROY){PostQuitMessage(0);return 0;}
    return DefWindowProcW(hwnd,message,wp,lp);
}
}
namespace ohno {
int show_install_wizard(SetupCallback install){
    WNDCLASSW wc{};wc.lpfnWndProc=on_message;wc.hInstance=GetModuleHandleW(nullptr);
    wc.lpszClassName=L"OhnoSetupWindowV1";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);
    wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
    if(!RegisterClassW(&wc)&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)return 1;
    Wizard state;state.action=install;
    HWND window=CreateWindowExW(0,wc.lpszClassName,L"Ohno - 安装课堂助手",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,490,300,nullptr,nullptr,wc.hInstance,&state);
    if(!window)return 1;
    ShowWindow(window,SW_SHOWNORMAL);UpdateWindow(window);
    MSG message{};
    while(GetMessageW(&message,nullptr,0,0)>0){
        if(!IsDialogMessageW(window,&message)){
            TranslateMessage(&message);DispatchMessageW(&message);
        }
    }
    return state.result;
}
}

namespace {
struct PasswordPrompt {
    HWND window=nullptr, edit=nullptr;
    const std::wstring* server=nullptr;
    std::wstring* output=nullptr;
    bool accepted=false, uninstall=false;
};
LRESULT CALLBACK password_message(HWND hwnd,UINT message,WPARAM wp,LPARAM lp){
    auto* state=reinterpret_cast<PasswordPrompt*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA));
    if(message==WM_NCCREATE){
        state=static_cast<PasswordPrompt*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        SetWindowLongPtrW(hwnd,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(state));return TRUE;
    }
    if(message==WM_CREATE&&state){
        state->window=hwnd;
        caption(hwnd,state->uninstall?L"卸载需要教师维护密码（不是课堂 PIN）":L"新增安装需要教师维护密码（不是课堂 PIN）",18,14,535);
        CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",state->server->c_str(),WS_VISIBLE|WS_CHILD|ES_READONLY|ES_AUTOHSCROLL,
            18,49,535,27,hwnd,nullptr,nullptr,nullptr);
        caption(hwnd,L"密码仅发送到上方教师端，不保存到本机或镜像。",18,88,535);
        state->edit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_VISIBLE|WS_CHILD|WS_TABSTOP|ES_PASSWORD|ES_AUTOHSCROLL,
            18,122,535,29,hwnd,reinterpret_cast<HMENU>(static_cast<INT_PTR>(201)),nullptr,nullptr);
        SendMessageW(state->edit,EM_SETLIMITTEXT,256,0);
        CreateWindowW(L"BUTTON",L"确认",WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_DEFPUSHBUTTON,
            327,171,105,32,hwnd,reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDOK)),nullptr,nullptr);
        CreateWindowW(L"BUTTON",L"取消",WS_VISIBLE|WS_CHILD|WS_TABSTOP,
            448,171,105,32,hwnd,reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)),nullptr,nullptr);
        SetFocus(state->edit);return 0;
    }
    if(message==WM_COMMAND&&state){
        if(LOWORD(wp)==IDOK){
            const int length=GetWindowTextLengthW(state->edit);
            if(length<=0||length>256){SetFocus(state->edit);return 0;}
            // Read directly into the caller-owned wiping buffer; do not leave
            // a password copy in the generic text helper's temporary vector.
            state->output->resize(static_cast<std::size_t>(length)+1);
            const int copied=GetWindowTextW(state->edit,state->output->data(),length+1);
            if(copied!=length){
                SecureZeroMemory(state->output->data(),state->output->size()*sizeof(wchar_t));
                state->output->clear();SetFocus(state->edit);return 0;
            }
            state->output->resize(static_cast<std::size_t>(length));
            SetWindowTextW(state->edit,L"");state->accepted=true;DestroyWindow(hwnd);return 0;
        }
        if(LOWORD(wp)==IDCANCEL){SetWindowTextW(state->edit,L"");DestroyWindow(hwnd);return 0;}
    }
    if(message==WM_CLOSE){if(state&&state->edit)SetWindowTextW(state->edit,L"");DestroyWindow(hwnd);return 0;}
    // No PostQuitMessage: this is a nested modal loop inside the setup wizard.
    if(message==WM_DESTROY)return 0;
    return DefWindowProcW(hwnd,message,wp,lp);
}
}
namespace ohno {
bool prompt_maintenance_password(const std::wstring& server,bool uninstall,std::wstring& output){
    WNDCLASSW wc{};wc.lpfnWndProc=password_message;wc.hInstance=GetModuleHandleW(nullptr);
    wc.lpszClassName=L"OhnoMaintenancePasswordV1";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);
    wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
    if(!RegisterClassW(&wc)&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)return false;
    PasswordPrompt state;state.server=&server;state.output=&output;state.uninstall=uninstall;
    HWND owner=GetActiveWindow();
    HWND window=CreateWindowExW(WS_EX_DLGMODALFRAME,wc.lpszClassName,L"Ohno - 教师维护授权",
        WS_POPUP|WS_CAPTION|WS_SYSMENU,CW_USEDEFAULT,CW_USEDEFAULT,590,255,owner,nullptr,wc.hInstance,&state);
    if(!window)return false;
    if(owner)EnableWindow(owner,FALSE);
    ShowWindow(window,SW_SHOWNORMAL);UpdateWindow(window);SetFocus(state.edit);
    MSG message{};bool quit=false;
    while(IsWindow(window)){
        const auto result=GetMessageW(&message,nullptr,0,0);
        if(result<=0){quit=result==0;DestroyWindow(window);break;}
        if(!IsDialogMessageW(window,&message)){TranslateMessage(&message);DispatchMessageW(&message);}
    }
    if(owner){EnableWindow(owner,TRUE);SetActiveWindow(owner);}
    if(quit)PostQuitMessage(static_cast<int>(message.wParam));
    return state.accepted;
}
}
