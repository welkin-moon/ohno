#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atomic>
#include <memory>
#include <string>
#include <stdexcept>
#include <thread>
#include "request_client.hpp"
#include "../src/policy.hpp"
namespace {
constexpr int site_id=101,request_id=102,pin_id=103,unlock_id=104,status_id=105;
struct Operation {
    HANDLE cancel=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    std::string request,result;
    std::atomic<bool> done{false};
    bool unlock=false;
    ~Operation(){if(!request.empty())SecureZeroMemory(request.data(),request.size());if(cancel)CloseHandle(cancel);}
};
struct Ui {
    HWND site=nullptr,pin=nullptr,status=nullptr,request=nullptr,unlock=nullptr,cancel=nullptr;
    std::shared_ptr<Operation> pending;
};
struct wipe {std::string& value;~wipe(){if(!value.empty())SecureZeroMemory(value.data(),value.size());}};
void busy(Ui& ui,bool active){
    for(HWND control:{ui.site,ui.pin,ui.request,ui.unlock})EnableWindow(control,!active);
    EnableWindow(ui.cancel,active);
}
void cancel(Ui& ui){
    SetWindowTextW(ui.pin,L"");
    if(ui.pending)SetEvent(ui.pending->cancel);
}
void begin(Ui& ui,std::string& payload,bool unlock){
    wipe secret{payload};
    if(ui.pending)return; // also reject duplicate synthetic button commands
    try {
        auto operation=std::make_shared<Operation>();
        if(!operation->cancel)throw std::runtime_error("cannot create cancel event");
        operation->request.assign(payload);operation->unlock=unlock;
        // A detached worker owns only its operation, never a window or Ui.
        // Closing the window can release Ui immediately; no stale HWND, queued
        // completion pointer or freed OVERLAPPED buffer is touched by the worker.
        std::thread([operation]{
            try{operation->result=send_teacher_request(operation->request,operation->cancel);}
            catch(...){operation->result="unavailable";}
            if(!operation->request.empty())SecureZeroMemory(operation->request.data(),operation->request.size());
            operation->done.store(true,std::memory_order_release);
        }).detach();
        ui.pending=std::move(operation);busy(ui,true);
        SetWindowTextW(ui.status,L"正在等待教师端…可以取消等待或直接关闭窗口。");
    }catch(...){SetWindowTextW(ui.status,L"无法开始请求，请检查本机服务。");}
}
void complete(Ui& ui){
    if(!ui.pending||!ui.pending->done.load(std::memory_order_acquire))return;
    const auto operation=std::move(ui.pending);busy(ui,false);
    const auto& result=operation->result;
    const wchar_t* text=L"未能确认结果，请查看教师端；不会自动重发。";
    if(result=="accepted")text=operation->unlock?L"PIN 验证通过，限制将在同步后暂停一小时。":L"申请已提交至教师端。";
    else if(result=="denied")text=L"验证失败、设备未批准或尝试次数过多。";
    else if(result=="notready")text=L"本机服务未就绪，请稍后再试。此请求尚未发送。";
    else if(result=="untrusted")text=L"本地服务身份不符，未发送请求或 PIN。请联系管理员。";
    else if(result=="cancelled")text=L"已取消等待；请求可能已执行，请查看教师端，不会自动重发。";
    else if(result=="timeout")text=L"等待超时；请求可能已执行，请查看教师端，不会自动重发。";
    SetWindowTextW(ui.status,text);
}
LRESULT CALLBACK handler(HWND window,UINT msg,WPARAM wp,LPARAM lp){
    auto* ui=reinterpret_cast<Ui*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(msg==WM_NCCREATE){
        ui=static_cast<Ui*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(ui));return DefWindowProcW(window,msg,wp,lp);
    }
    if(msg==WM_CREATE&&ui){
        auto control=[&](const wchar_t* kind,const wchar_t* text,DWORD style,int x,int y,int w,int h,int id,DWORD ex=0){
            return CreateWindowExW(ex,kind,text,WS_CHILD|WS_VISIBLE|style,x,y,w,h,window,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),nullptr,nullptr);
        };
        control(L"STATIC",L"输入网站域名（例如 game.example）：",0,18,15,370,24,0);
        ui->site=control(L"EDIT",L"",WS_TABSTOP|ES_AUTOHSCROLL,18,44,350,27,site_id,WS_EX_CLIENTEDGE);
        SendMessageW(ui->site,EM_SETLIMITTEXT,253,0);
        ui->request=control(L"BUTTON",L"向教师申请",WS_TABSTOP,18,82,130,30,request_id);
        control(L"STATIC",L"教师解锁 PIN（4 到 8 位数字，临时解除 1 小时）：",0,18,128,370,24,0);
        ui->pin=control(L"EDIT",L"",WS_TABSTOP|ES_PASSWORD|ES_AUTOHSCROLL,18,157,350,27,pin_id,WS_EX_CLIENTEDGE);
        SendMessageW(ui->pin,EM_SETLIMITTEXT,128,0);
        ui->unlock=control(L"BUTTON",L"教师解锁",WS_TABSTOP,18,195,130,30,unlock_id);
        ui->cancel=control(L"BUTTON",L"取消等待",WS_TABSTOP,165,195,130,30,IDCANCEL);
        ui->status=control(L"STATIC",L"",0,18,235,370,58,status_id);
        control(L"STATIC",L"PIN 仅用于现场临时解锁；后台管理页只在教师机本地开放。",0,18,301,375,42,0);
        if(!ui->site||!ui->pin||!ui->request||!ui->unlock||!ui->cancel||!ui->status||!SetTimer(window,1,50,nullptr))return -1;
        busy(*ui,false);SetFocus(ui->site);return 0;
    }
    if(msg==WM_TIMER&&ui){complete(*ui);return 0;}
    if(msg==WM_COMMAND&&ui){
        const int id=LOWORD(wp);
        if(id==IDCANCEL){
            if(ui->pending){cancel(*ui);EnableWindow(ui->cancel,FALSE);SetWindowTextW(ui->status,L"正在取消等待；已发送的请求不能靠关闭窗口撤回。");}
            else SendMessageW(window,WM_CLOSE,0,0);
            return 0;
        }
        if(ui->pending)return 0;
        if(id==request_id){
            wchar_t text[254]{};const int len=GetWindowTextW(ui->site,text,254);std::string host;
            for(int i=0;i<len;++i){wchar_t c=text[i];if(c>=L'A'&&c<=L'Z')c+=L'a'-L'A';if(c>127){host.clear();break;}host+=static_cast<char>(c);}
            if(!ohno::valid_hostname(host)){SetWindowTextW(ui->status,L"请输入域名，不要输入 https:// 或路径。");return 0;}
            std::string payload="W:"+host;begin(*ui,payload,false);return 0;
        }
        if(id==unlock_id){
            wchar_t text[129]{};const int len=GetWindowTextW(ui->pin,text,129);SetWindowTextW(ui->pin,L"");
            std::string payload;payload.reserve(10);payload="U:";bool valid=len>=4&&len<=8;
            for(int i=0;i<len&&valid;++i){if(text[i]<L'0'||text[i]>L'9')valid=false;else payload+=static_cast<char>(text[i]);}
            SecureZeroMemory(text,sizeof(text));
            if(!valid){SecureZeroMemory(payload.data(),payload.size());SetWindowTextW(ui->status,L"请输入 4 到 8 位数字 PIN。");return 0;}
            begin(*ui,payload,true);return 0;
        }
    }
    if(msg==WM_CLOSE){if(ui)cancel(*ui);DestroyWindow(window);return 0;}
    if(msg==WM_DESTROY){if(ui){cancel(*ui);ui->pending.reset();}KillTimer(window,1);PostQuitMessage(0);return 0;}
    return DefWindowProcW(window,msg,wp,lp);
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int show){
    Ui ui;WNDCLASSW wc{};wc.lpfnWndProc=handler;wc.hInstance=instance;wc.lpszClassName=L"OhnoRequestWindow";
    wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
    if(!RegisterClassW(&wc))return 1;
    HWND window=CreateWindowW(wc.lpszClassName,L"ohno 申请与临时解锁",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,410,390,nullptr,nullptr,instance,&ui);
    if(!window)return 1;ShowWindow(window,show);UpdateWindow(window);MSG msg{};
    while(GetMessageW(&msg,nullptr,0,0)>0){if(!IsDialogMessageW(window,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}}
    return 0;
}
