// Test-only CLI. Production GUI calls the same authenticated pipe client.
#include <cstdio>
#include <string>
#include <windows.h>
#include "../windows/request_client.hpp"
namespace {
struct handle {HANDLE value=nullptr;~handle(){if(value)CloseHandle(value);}};
struct restricted_caller {
    handle original,restricted;bool active=false;
    bool enter(){
        if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&original.value))return false;
        BYTE admin[SECURITY_MAX_SID_SIZE]{};DWORD size=sizeof(admin);
        if(!CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,admin,&size))return false;
        SID_AND_ATTRIBUTES disable{admin,0};
        // Only reduce this test process's effective token; no accounts, system
        // policy, privileges or persistent security descriptors are modified.
        if(!CreateRestrictedToken(original.value,DISABLE_MAX_PRIVILEGE,1,&disable,0,nullptr,0,nullptr,&restricted.value)||
            !ImpersonateLoggedOnUser(restricted.value))return false;
        active=true;BOOL administrator=TRUE;
        return CheckTokenMembership(nullptr,admin,&administrator)&&!administrator;
    }
    ~restricted_caller(){if(active&&!RevertToSelf())TerminateProcess(GetCurrentProcess(),1);}
};
}
int main(int argc,char** argv){
    if(argc!=2)return 1;
    restricted_caller caller;if(!caller.enter()){std::fputs("restricted fixture token failed\n",stderr);return 4;}
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
