#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <cstdlib>
int main(int argc,char** argv){
 if(argc!=2)return 3;WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data))return 4;
 SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(s==INVALID_SOCKET)return 5;
 sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(static_cast<u_short>(std::atoi(argv[1])));
 int ok=connect(s,reinterpret_cast<sockaddr*>(&address),sizeof(address));closesocket(s);WSACleanup();return ok==0?0:1;
}
