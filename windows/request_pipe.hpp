#pragma once
#include <windows.h>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
class RequestPipe {
    HANDLE stop_;
    std::mutex mutex_;
    std::set<std::string> pending_;
    std::thread worker_;
    void serve();
public:
    explicit RequestPipe(HANDLE stop);
    ~RequestPipe();
    RequestPipe(const RequestPipe&)=delete;
    RequestPipe& operator=(const RequestPipe&)=delete;
    std::vector<std::string> take();
};
