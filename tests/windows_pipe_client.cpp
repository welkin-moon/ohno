#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring>
int main(int argc,char** argv){
 if(argc!=2)return 1;
 for(int i=0;i<20;++i){
  HANDLE pipe=CreateFileW(L"\\\\.\\pipe\\OhnoWebsiteRequest",FILE_WRITE_DATA|SYNCHRONIZE,0,nullptr,OPEN_EXISTING,0,nullptr);
  if(pipe!=INVALID_HANDLE_VALUE){DWORD sent=0;DWORD size=static_cast<DWORD>(std::strlen(argv[1]));BOOL ok=WriteFile(pipe,argv[1],size,&sent,nullptr);CloseHandle(pipe);return ok&&sent==size?0:2;}
  Sleep(500);
 }
 return 3;
}
