// Test-only CLI. Production GUI calls the same authenticated pipe client.
#include <cstdio>
#include <string>
#include <windows.h>
#include "../windows/request_client.hpp"
int main(int argc,char** argv){
    if(argc!=2)return 1;
    // Retry only when no pipe handle was opened and no bytes could be sent.
    // Never replay a possibly executed operation; production GUI tries once.
    for(int i=0;i<20;++i){
        std::string message=argv[1];const auto result=send_teacher_request(message);
        if(result=="accepted")return 0;
        if(result!="notready")return 2;
        Sleep(500);
    }
    std::fputs("trusted request pipe unavailable\n",stderr);return 3;
}
