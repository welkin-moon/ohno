#pragma once
#include <cctype>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
namespace ohno_json {
struct value {
    enum class kind { null, boolean, number, string, array, object } type = kind::null;
    bool boolean = false;
    std::string text;
    std::vector<value> items;
    std::map<std::string,value> fields;
    const value& at(const std::string& key) const {
        if (type != kind::object) throw std::runtime_error("not an object");
        return fields.at(key);
    }
};
class parser {
    const std::string& s; std::size_t i=0; unsigned depth=0;
    void ws(){while(i<s.size() && (s[i]==' '||s[i]=='\t'||s[i]=='\r'||s[i]=='\n')) ++i;}
    bool take(char c){ws();if(i<s.size()&&s[i]==c){++i;return true;}return false;}
    [[noreturn]] void fail(){throw std::runtime_error("invalid JSON");}
    static void utf8(std::string& out,unsigned x){
        if(x<0x80)out.push_back(static_cast<char>(x));
        else if(x<0x800){out.push_back(static_cast<char>(0xc0|(x>>6)));out.push_back(static_cast<char>(0x80|(x&63)));}
        else if(x<0x10000){out.push_back(static_cast<char>(0xe0|(x>>12)));out.push_back(static_cast<char>(0x80|((x>>6)&63)));out.push_back(static_cast<char>(0x80|(x&63)));}
        else{out.push_back(static_cast<char>(0xf0|(x>>18)));out.push_back(static_cast<char>(0x80|((x>>12)&63)));out.push_back(static_cast<char>(0x80|((x>>6)&63)));out.push_back(static_cast<char>(0x80|(x&63)));}
    }
    unsigned hex4(){unsigned x=0;for(int k=0;k<4;k++){if(i>=s.size())fail();char c=s[i++];x<<=4;if(c>='0'&&c<='9')x+=c-'0';else if(c>='a'&&c<='f')x+=10+c-'a';else if(c>='A'&&c<='F')x+=10+c-'A';else fail();}return x;}
    std::string str(){
        if(!take('"')) fail();
        std::string out;
        while(i<s.size()) { unsigned char c=static_cast<unsigned char>(s[i++]);if(c=='"')return out;if(c<0x20)fail();if(c!='\\'){out.push_back(static_cast<char>(c));continue;}if(i>=s.size())fail();
            c=static_cast<unsigned char>(s[i++]);switch(c){case '"':case '\\':case '/':out.push_back(static_cast<char>(c));break;case 'b':out.push_back('\b');break;case 'f':out.push_back('\f');break;case 'n':out.push_back('\n');break;case 'r':out.push_back('\r');break;case 't':out.push_back('\t');break;case 'u':{unsigned x=hex4();if(x>=0xd800&&x<=0xdbff){if(i+1>=s.size()||s[i++]!='\\'||s[i++]!='u')fail();unsigned y=hex4();if(y<0xdc00||y>0xdfff)fail();x=0x10000+((x-0xd800)<<10)+(y-0xdc00);}else if(x>=0xdc00&&x<=0xdfff)fail();utf8(out,x);break;}default:fail();}}
        fail();
    }
    value parse_value(){
        ws();if(i>=s.size()||depth++>=32)fail();value v;
        if(s[i]=='"'){v.type=value::kind::string;v.text=str();}
        else if(s[i]=='{'){++i;v.type=value::kind::object;if(!take('}'))for(;;){auto k=str();if(!take(':'))fail();auto item=parse_value();if(!v.fields.emplace(k,std::move(item)).second)fail();if(take('}'))break;if(!take(','))fail();}}
        else if(s[i]=='['){++i;v.type=value::kind::array;if(!take(']'))for(;;){v.items.push_back(parse_value());if(take(']'))break;if(!take(','))fail();}}
        else if(s.compare(i,4,"null")==0){i+=4;}
        else if(s.compare(i,4,"true")==0){i+=4;v.type=value::kind::boolean;v.boolean=true;}
        else if(s.compare(i,5,"false")==0){i+=5;v.type=value::kind::boolean;}
        else {auto begin=i;if(s[i]=='-')++i;if(i>=s.size())fail();if(s[i]=='0')++i;else{if(s[i]<'1'||s[i]>'9')fail();while(i<s.size()&&s[i]>='0'&&s[i]<='9')++i;}if(i<s.size()&&s[i]=='.'){++i;if(i>=s.size()||s[i]<'0'||s[i]>'9')fail();while(i<s.size()&&s[i]>='0'&&s[i]<='9')++i;}if(i<s.size()&&(s[i]=='e'||s[i]=='E')){++i;if(i<s.size()&&(s[i]=='+'||s[i]=='-'))++i;if(i>=s.size()||s[i]<'0'||s[i]>'9')fail();while(i<s.size()&&s[i]>='0'&&s[i]<='9')++i;}v.type=value::kind::number;v.text=s.substr(begin,i-begin);}
        --depth;return v;
    }
public:
    explicit parser(const std::string& x):s(x){}
    value run(){if(s.size()>1024*1024)fail();value v=parse_value();ws();if(i!=s.size())fail();return v;}
};
inline value parse(const std::string& s){return parser(s).run();}
}
