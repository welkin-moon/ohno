#include "smbios.hpp"
#include <cassert>
#include <iostream>
int main(){
 std::vector<std::uint8_t> b(34);b[4]=26;b[8]=1;b[9]=24;
 for(unsigned i=0;i<16;i++)b[16+i]=static_cast<std::uint8_t>(i+1);
 assert(ohno::smbios_uuid(b)=="0102030405060708090a0b0c0d0e0f10");
 auto c=b;for(unsigned i=0;i<16;i++)c[16+i]=0;assert(ohno::smbios_uuid(c).empty());
 c=b;c[4]=100;assert(ohno::smbios_uuid(c).empty());c=b;c[9]=3;assert(ohno::smbios_uuid(c).empty());
 assert(ohno::smbios_uuid({}).empty());std::cout<<"SMBIOS tests passed\n";
}
