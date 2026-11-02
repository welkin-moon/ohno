// Test-only native caller for daily device routes. All inputs on stdin, no
// registry/service/trust-store mutation, and output contains no credentials.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <string>
#include "../src/json.hpp"
#include "../windows/trusted_http.hpp"
namespace {
void erase(std::string& text){if(!text.empty())SecureZeroMemory(text.data(),text.size());}
struct input {
    std::string text,body;ohno_json::value json;
    ~input(){erase(text);erase(body);for(auto& field:json.fields)erase(field.second.text);}
};
std::wstring wide(const std::string& text){
    if(text.empty()||text.size()>1024)throw 1;
    const int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);
    if(count<=0)throw 1;std::wstring result(static_cast<std::size_t>(count),0);
    if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),result.data(),count))throw 1;
    return result;
}
}
int main(){
    try{
        input data;data.text.reserve(32768);
        for(int ch;(ch=std::getchar())!=EOF;){if(data.text.size()>=32768)throw 1;data.text+=static_cast<char>(ch);}
        data.json=ohno_json::parse(data.text);
        if(data.json.type!=ohno_json::value::kind::object||data.json.fields.size()!=4)throw 1;
        auto field=[&](const char* key)->const std::string&{const auto& value=data.json.at(key);if(value.type!=ohno_json::value::kind::string)throw 1;return value.text;};
        const auto server=wide(field("server")),path=wide(field("path"));const auto certificate=field("certificate_pem");
        data.body=field("body");
        const auto limit=path==L"/api/device/policy"?1024u*1024u:8192u;
        const auto result=ohno::trusted_post(ohno::TrustedPost{server,certificate,path,data.body,limit});
        const char* failure=result.failure==ohno::TrustedHttpFailure::None?"None":result.failure==ohno::TrustedHttpFailure::Unavailable?"Unavailable":"InvalidResponse";
        std::printf("%s %lu %zu\n",failure,result.status,result.body.size());return 0;
    }catch(...){std::puts("InvalidInput");return 2;}
}
