#pragma once
#include <windows.h>
#include <functional>
#include <string>
#include <thread>
class RequestPipe {
    HANDLE stop_;
    std::function<std::string(const std::string&)> callback_;
    std::thread worker_;
    void serve();
public:
    RequestPipe(HANDLE stop,std::function<std::string(const std::string&)> callback);
    ~RequestPipe();
    RequestPipe(const RequestPipe&)=delete;
    RequestPipe& operator=(const RequestPipe&)=delete;
};
