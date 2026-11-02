#pragma once
#include <windows.h>
#include <functional>
#include <string>
#include <thread>
#include <atomic>
class RequestPipe {
    std::atomic<bool> available_{false};
    HANDLE stop_;
    std::function<std::string(const std::string&)> callback_;
    std::thread worker_;
    void serve();
public:
    RequestPipe(HANDLE stop,std::function<std::string(const std::string&)> callback);
    ~RequestPipe();
    bool available() const {return available_.load();}
    RequestPipe(const RequestPipe&)=delete;
    RequestPipe& operator=(const RequestPipe&)=delete;
};
