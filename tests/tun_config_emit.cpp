#include "tun_config.hpp"
#include <cstring>
#include <iostream>
int main(int argc, char** argv){
    if(argc>1 && std::strcmp(argv[1],"--whitelist")==0)
        std::cout<<ohno::tun_config_mode(true,{"edu.cn","school.lan"},{".extra.example"});
    else
        std::cout<<ohno::tun_config({"classic.minecraft.net","eaglercraft.com"},{".classic.minecraft.net"});
}
