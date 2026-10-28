#include "tun_config.hpp"
#include "json.hpp"
#include <cassert>
#include <iostream>
int main(){
 auto p=ohno_json::parse(ohno::tun_config({"game.example","file://*"},{".allowed.game.example"}));
 auto& in=p.at("inbounds").items[0];assert(in.at("type").text=="tun");assert(in.at("auto_route").boolean);
 auto& rules=p.at("route").at("rules").items;assert(rules.size()==3);assert(rules[1].at("domain").items[0].text=="allowed.game.example");assert(rules[2].at("domain_suffix").items[0].text=="game.example");
 bool bad=false;try{ohno::tun_config({"bad domain"},{});}catch(const std::runtime_error&){bad=true;}assert(bad);
 std::cout<<"TUN configuration tests passed\n";
}
