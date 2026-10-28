#pragma once
#include <windows.h>
#include <string>
#include <vector>
class TunManager {
    HANDLE stop_;
    HANDLE job_=nullptr,process_=nullptr;
    std::wstring dir_;
    std::string config_;
    ULONGLONG last_attempt_=0;
    void stop_child();
    bool start(const std::string& config);
public:
    explicit TunManager(HANDLE stop);
    ~TunManager();
    TunManager(const TunManager&)=delete;
    TunManager& operator=(const TunManager&)=delete;
    bool ensure(const std::vector<std::string>& blocked,const std::vector<std::string>& allowed);
};
