#include "json.hpp"
#include <cassert>
#include <iostream>
using namespace ohno_json;
int main(){
 auto v=parse("{\"revision\":3,\"web_domains\":[\"game.example\"],\"approved\":true,\"title\":\"\\u4e2d\\ud83d\\ude00\"}");
 assert(v.at("revision").text=="3");assert(v.at("web_domains").items[0].text=="game.example");assert(v.at("approved").boolean);
 assert(v.at("title").text=="\xe4\xb8\xad\xf0\x9f\x98\x80");
 for(const auto* s:{"{\"x\":1,\"x\":2}","[01]","\"\\ud800\"","[true,]","1x"}){bool bad=false;try{parse(s);}catch(const std::runtime_error&){bad=true;}assert(bad);}
 std::cout<<"JSON tests passed\n";
}
