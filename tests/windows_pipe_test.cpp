#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <string>
#include "../windows/request_pipe.hpp"
int main(){
 HANDLE stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!stop)return 1;
 int result=3;
 {
  RequestPipe server(stop,[](const std::string& payload){return payload=="W:game.example"?"accepted":"invalid";});
  for(int i=0;i<20;i++){
   HANDLE pipe=CreateFileW(L"\\\\.\\pipe\\OhnoWebsiteRequest",FILE_READ_DATA|FILE_WRITE_DATA|SYNCHRONIZE,0,nullptr,OPEN_EXISTING,0,nullptr);
   if(pipe!=INVALID_HANDLE_VALUE){
    const char data[]="W:game.example";DWORD sent=0,count=0;char reply[64]{};BOOL ok=WriteFile(pipe,data,sizeof(data)-1,&sent,nullptr);
    if(ok)ok=ReadFile(pipe,reply,sizeof(reply),&count,nullptr);
    if(ok){char ack='1';DWORD n=0;WriteFile(pipe,&ack,1,&n,nullptr);}
    CloseHandle(pipe);result=ok&&std::string(reply,count)=="accepted"?0:4;break;
   }
   if(i==19)std::fprintf(stderr,"pipe open failed: %lu\n",GetLastError());Sleep(500);
  }
  SetEvent(stop);
 }
 CloseHandle(stop);return result;
}
