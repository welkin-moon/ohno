#pragma once
#include <windows.h>
#include <fwpmu.h>
#include <map>
#include <string>
#include <vector>
// Experimental per-program WFP outbound block; dynamic session automatically
// removes these filters when the service exits. Not a malware security boundary.
class NetworkFilter {
    struct Item { std::string hash; UINT64 v4=0,v6=0; bool blocked=false; };
    HANDLE engine_=nullptr;
    bool paused_=false,cycle_ok_=true;
    GUID sublayer_{};
    std::map<std::wstring,Item> items_;
    std::vector<std::string> allowed_;
    bool granted(const Item& item) const;
    bool add(const std::wstring&,Item&);
    void remove(Item&);
public:
    NetworkFilter();
    ~NetworkFilter();
    NetworkFilter(const NetworkFilter&)=delete;
    NetworkFilter& operator=(const NetworkFilter&)=delete;
    bool available() const {return engine_!=nullptr;}
    // An uncertain filter mutation remains unhealthy until worker restart.
    void begin_cycle(){cycle_ok_=cycle_ok_&&available();}
    bool cycle_healthy() const {return available()&&cycle_ok_;}
    bool register_untrusted(const std::wstring& path,const std::string& hash);
    void apply_grants(const std::vector<std::string>& hashes);
    void set_paused(bool paused);
};
