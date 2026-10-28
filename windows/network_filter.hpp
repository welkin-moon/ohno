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
    bool paused_=false;
    GUID sublayer_{};
    std::map<std::wstring,Item> items_;
    bool add(const std::wstring&,Item&);
    void remove(Item&);
public:
    NetworkFilter();
    ~NetworkFilter();
    NetworkFilter(const NetworkFilter&)=delete;
    NetworkFilter& operator=(const NetworkFilter&)=delete;
    bool available() const {return engine_!=nullptr;}
    bool register_untrusted(const std::wstring& path,const std::string& hash);
    void apply_grants(const std::vector<std::string>& hashes);
    void set_paused(bool paused);
};
