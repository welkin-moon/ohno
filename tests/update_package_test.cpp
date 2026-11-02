#include "update_package.hpp"
#include <cassert>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
using namespace ohno;
void reject(const std::function<void()>& f){bool bad=false;try{f();}catch(const std::exception&){bad=true;}assert(bad);}
void le(std::string& out,std::size_t offset,std::uint64_t value,unsigned count){for(unsigned i=0;i<count;++i)out[offset+i]=static_cast<char>((value>>(i*8))&255);}
int main(int argc,char** argv){
    if(argc==2){std::ifstream in(argv[1],std::ios::binary);std::string data(std::istreambuf_iterator<char>(in),{});try{auto p=parse_update_package(data);std::cout<<p.version;return 0;}catch(const std::exception&){return 1;}}
    std::string exe(1024,'\0');exe.replace(0,2,"MZ");le(exe,0x3c,0x80,4);exe.replace(0x80,4,std::string("PE\0\0",4));le(exe,0x84,0x8664,2);le(exe,0x94,2,2);le(exe,0x98,0x20b,2);
    std::string package(60,'\0');package.replace(0,8,"OHNOPK01");le(package,8,5,2);le(package,10,6,2);
    for(unsigned i=0;i<6;++i)le(package,12+i*8,i<4?1024:8,8);
    package+="0.2.0";for(unsigned i=0;i<4;++i)package+=exe;package+="license\nlicense\n";
    auto parsed=parse_update_package(package);assert(parsed.version=="0.2.0");assert(parsed.files[0].offset==65);assert(parsed.files[5].size==8);
    for(std::size_t i=0;i<package.size();++i)reject([&]{parse_update_package(package.substr(0,i));});
    reject([&]{parse_update_package(package+"x");});
    for(unsigned index=0;index<6;++index)for(auto size:{0ULL,0xffffffffffffffffULL,0x100000000ULL}){
        auto bad=package;le(bad,12+index*8,size,8);reject([&]{parse_update_package(bad);});}
    for(auto offset:{8U,10U,65U,65U+0x3c,65U+0x84,65U+0x98}){auto bad=package;bad[offset]='x';reject([&]{parse_update_package(bad);});}
    std::cout<<"Fixed-layout package bounds, PE32+ architecture and truncation tests passed\n";
}
