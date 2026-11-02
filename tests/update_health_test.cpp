#include "update_health.hpp"
#include <cassert>
#include <functional>
#include <iostream>
using namespace ohno;
void rejects(const std::function<void()>& fn){bool bad=false;try{fn();}catch(...){bad=true;}assert(bad);}
int main(){
    UpdateHealth proof{std::string(64,'a'),{7,"0.2.0",std::string(64,'b')},1};
    const auto document=serialize_update_health(proof);const auto parsed=parse_update_health(document);
    assert(parsed.transaction==proof.transaction&&parsed.revision==proof.revision&&parsed.successful_agent_cycles==1);
    for(std::size_t i=0;i<document.size()-1;++i)rejects([&]{parse_update_health(document.substr(0,i));});
    for(const auto& replacement:std::vector<std::pair<std::string,std::string>>{
        {"\"cycles\":1","\"cycles\":0"},{"\"cycles\":1","\"cycles\":true"},
        {"\"cycles\":1","\"cycles\":-1"},{"\"cycles\":1","\"cycles\":1,\"extra\":1"},
        {"\"cycles\":1","\"cycles\":1,\"cycles\":1"},{"\"sequence\":7","\"sequence\":-1"}}){
        auto bad=document;bad.replace(bad.find(replacement.first),replacement.first.size(),replacement.second);rejects([&]{parse_update_health(bad);});
    }
    rejects([&]{parse_update_health(document+std::string(512,' '));});
    proof.transaction="";rejects([&]{serialize_update_health(proof);});
    std::cout<<"Private worker health framing and strict bindings passed\n";
}
