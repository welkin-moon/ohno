#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring>
#include <cstdio>
#include <string>
int main(int argc,char** argv){
 if(argc!=2)return 1;
 for(int i=0;i<20;++i){
  HANDLE pipe=CreateFileW(L"\\\\.\\pipe\\OhnoWebsiteRequest",FILE_READ_DATA|FILE_WRITE_DATA|SYNCHRONIZE,0,nullptr,OPEN_EXISTING,0,nullptr);
  if(pipe!=INVALID_HANDLE_VALUE){DWORD sent=0;DWORD size=static_cast<DWORD>(std::strlen(argv[1]));BOOL ok=WriteFile(pipe,argv[1],size,&sent,nullptr);char reply[64]{};DWORD n=0;if(ok)ok=ReadFile(pipe,reply,sizeof(reply),&n,nullptr);if(ok){char ack='1';DWORD count=0;WriteFile(pipe,&ack,1,&count,nullptr);}CloseHandle(pipe);return ok&&sent==size&&std::string(reply,n)=="accepted"?0:2;}
  if(i==19)std::fprintf(stderr,"pipe open failed: %lu\n",GetLastError());
  Sleep(500);
 }
 return 3;
}
