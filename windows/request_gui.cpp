#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include "../src/policy.hpp"
namespace {
HWND site_edit=nullptr,pin_edit=nullptr;
std::string utf8(const std::wstring& text){
 if(text.empty())return {};int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0,nullptr,nullptr);
 if(n<=0)return {};std::string s(static_cast<std::size_t>(n),'\0');if(!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),s.data(),n,nullptr,nullptr))return {};return s;
}
std::string send(std::string& message){
 HANDLE pipe=CreateFileW(L"\\\\.\\pipe\\OhnoWebsiteRequest",FILE_READ_DATA|FILE_WRITE_DATA|SYNCHRONIZE,0,nullptr,OPEN_EXISTING,0,nullptr);
 if(pipe==INVALID_HANDLE_VALUE){SecureZeroMemory(message.data(),message.size());return "unavailable";}
 DWORD sent=0;BOOL ok=WriteFile(pipe,message.data(),static_cast<DWORD>(message.size()),&sent,nullptr);
 SecureZeroMemory(message.data(),message.size());
 char reply[64]{};DWORD count=0;if(ok)ok=ReadFile(pipe,reply,sizeof(reply),&count,nullptr);
 if(ok){char ack='1';DWORD n=0;WriteFile(pipe,&ack,1,&n,nullptr);}CloseHandle(pipe);
 return ok?std::string(reply,count):"unavailable";
}
LRESULT CALLBACK handler(HWND window,UINT msg,WPARAM wp,LPARAM lp){
 if(msg==WM_CREATE){
  CreateWindowW(L"STATIC",L"输入网站域名（例如 game.example）：",WS_CHILD|WS_VISIBLE,18,15,370,24,window,nullptr,nullptr,nullptr);
  site_edit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,18,44,350,27,window,reinterpret_cast<HMENU>(1),nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"向教师申请",WS_CHILD|WS_VISIBLE|WS_TABSTOP,18,82,130,30,window,reinterpret_cast<HMENU>(2),nullptr,nullptr);
  CreateWindowW(L"STATIC",L"教师解锁 PIN（4–8 位数字，临时解除 1 小时）：",WS_CHILD|WS_VISIBLE,18,128,370,24,window,nullptr,nullptr,nullptr);
  pin_edit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_PASSWORD|ES_AUTOHSCROLL,18,157,350,27,window,reinterpret_cast<HMENU>(3),nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"教师解锁",WS_CHILD|WS_VISIBLE|WS_TABSTOP,18,195,130,30,window,reinterpret_cast<HMENU>(4),nullptr,nullptr);
  CreateWindowW(L"STATIC",L"PIN 仅用于现场临时解锁；后台管理页只在教师机本地开放。",WS_CHILD|WS_VISIBLE,18,235,375,42,window,nullptr,nullptr,nullptr);return 0;
 }
 if(msg==WM_COMMAND&&LOWORD(wp)==2){
  wchar_t text[254]{};int len=GetWindowTextW(site_edit,text,254);std::string host;
  for(int i=0;i<len;++i){wchar_t c=text[i];if(c>=L'A'&&c<=L'Z')c+=L'a'-L'A';if(c>127){host.clear();break;}host+=static_cast<char>(c);}
  if(!ohno::valid_hostname(host)){MessageBoxW(window,L"请输入域名，不要输入 https:// 或路径。",L"ohno",MB_OK|MB_ICONWARNING);return 0;}
  std::string payload="W:"+host;auto result=send(payload);
  MessageBoxW(window,result=="accepted"?L"申请已提交至教师端。":L"无法提交。请检查服务、设备审批和网络。",L"ohno",MB_OK|(result=="accepted"?MB_ICONINFORMATION:MB_ICONERROR));return 0;
 }
 if(msg==WM_COMMAND&&LOWORD(wp)==4){
  wchar_t text[129]{};int len=GetWindowTextW(pin_edit,text,129);SetWindowTextW(pin_edit,L"");
  std::wstring pin(text,static_cast<std::size_t>(len));SecureZeroMemory(text,sizeof(text));std::string encoded=utf8(pin);SecureZeroMemory(pin.data(),pin.size()*sizeof(wchar_t));
  if(encoded.size()<4||encoded.size()>8||encoded.find_first_not_of("0123456789")!=std::string::npos){SecureZeroMemory(encoded.data(),encoded.size());MessageBoxW(window,L"请输入 4–8 位数字 PIN。",L"ohno",MB_OK|MB_ICONWARNING);return 0;}
  std::string payload="U:"+encoded;SecureZeroMemory(encoded.data(),encoded.size());auto result=send(payload);
  MessageBoxW(window,result=="accepted"?L"教师验证通过，本机限制将在同步后暂停一小时。":result=="denied"?L"验证失败或尝试次数过多。":L"无法联系教师端。",L"ohno",MB_OK|(result=="accepted"?MB_ICONINFORMATION:MB_ICONERROR));return 0;
 }
 if(msg==WM_DESTROY){PostQuitMessage(0);return 0;}return DefWindowProcW(window,msg,wp,lp);
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int show){
 WNDCLASSW wc{};wc.lpfnWndProc=handler;wc.hInstance=instance;wc.lpszClassName=L"OhnoRequestWindow";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
 if(!RegisterClassW(&wc))return 1;
 HWND window=CreateWindowW(wc.lpszClassName,L"ohno 申请与临时解锁",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,CW_USEDEFAULT,CW_USEDEFAULT,410,325,nullptr,nullptr,instance,nullptr);
 if(!window)return 1;ShowWindow(window,show);UpdateWindow(window);MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return 0;
}
