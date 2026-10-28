#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include "../src/policy.hpp"
namespace {
HWND edit=nullptr;
LRESULT CALLBACK handler(HWND window,UINT msg,WPARAM wp,LPARAM lp){
    if(msg==WM_CREATE){
        CreateWindowW(L"STATIC",L"输入网站域名（例如 game.example）：",WS_CHILD|WS_VISIBLE,18,18,370,24,window,nullptr,nullptr,nullptr);
        edit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,18,48,350,28,window,reinterpret_cast<HMENU>(1),nullptr,nullptr);
        CreateWindowW(L"BUTTON",L"向教师申请",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,18,92,130,34,window,reinterpret_cast<HMENU>(2),nullptr,nullptr);return 0;
    }
    if(msg==WM_COMMAND&&LOWORD(wp)==2){
        wchar_t text[254]{};int len=GetWindowTextW(edit,text,254);std::string host;
        for(int i=0;i<len;++i){wchar_t c=text[i];if(c>=L'A'&&c<=L'Z')c+=L'a'-L'A';if(c>127){host.clear();break;}host+=static_cast<char>(c);}
        if(!ohno::valid_hostname(host)){MessageBoxW(window,L"请输入域名，不要输入 https:// 或路径。",L"ohno",MB_OK|MB_ICONWARNING);return 0;}
        HANDLE pipe=CreateFileW(L"\\\\.\\pipe\\OhnoWebsiteRequest",FILE_WRITE_DATA|SYNCHRONIZE,0,nullptr,OPEN_EXISTING,0,nullptr);
        if(pipe==INVALID_HANDLE_VALUE){MessageBoxW(window,L"无法联系本机课堂服务，请稍后重试。",L"ohno",MB_OK|MB_ICONERROR);return 0;}
        DWORD sent=0;BOOL ok=WriteFile(pipe,host.data(),static_cast<DWORD>(host.size()),&sent,nullptr);CloseHandle(pipe);
        MessageBoxW(window,ok&&sent==host.size()?L"申请已交给本机服务，等待同步到教师端。":L"无法提交申请，请稍后重试。",L"ohno",MB_OK|(ok?MB_ICONINFORMATION:MB_ICONERROR));return 0;
    }
    if(msg==WM_DESTROY){PostQuitMessage(0);return 0;}return DefWindowProcW(window,msg,wp,lp);
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int show){
    WNDCLASSW wc{};wc.lpfnWndProc=handler;wc.hInstance=instance;wc.lpszClassName=L"OhnoRequestWindow";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
    if(!RegisterClassW(&wc))return 1;
    HWND window=CreateWindowW(wc.lpszClassName,L"ohno 网站解锁申请",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,CW_USEDEFAULT,CW_USEDEFAULT,410,180,nullptr,nullptr,instance,nullptr);
    if(!window)return 1;ShowWindow(window,show);UpdateWindow(window);MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return 0;
}
