# Windows 10 兼容性检查与服务骨架

## 先在一台测试机检查

`ohno-check.cmd` 是只读检查，运行不需要 .NET，也不主动请求管理员权限。它查询系统版本、架构、BFE/防火墙等服务和常见系统工具，不会更改系统设置。请从资源管理器双击运行并提供窗口输出。它不能证明所有 WFP 接口可用、网络驱动兼容或后续安装一定成功。`where` 不可用时检查结果可能不准确。出于隐私，它不主动读取账号名、IP 或个人文件。

## 服务骨架

`service.cpp` 是原生 Win32 单服务的生命周期骨架：接收 SCM 启动、停止和关机消息。当前没有联网、拦截、教师身份验证、安装或服务崩溃恢复配置，也不能作为成品部署。

在 Windows 10 x64 的 Visual Studio 开发者命令行中，使用 Windows SDK 编译（这里尚未实测）：

```
cl /std:c++17 /EHsc /W4 /MT /DUNICODE /D_UNICODE service.cpp /Fe:ohno-service-prototype.exe advapi32.lib
```

构建需要编译器及 SDK，成品运行时按 `/MT` 静态链接 C/C++ 运行库，不需要另装 .NET 或 Visual C++ 再发行包。精简系统可能缺失 Windows 自身的基础组件，必须通过实机检查和测试。

源码不包含自动安装指令，避免在未经测试的镜像中注册一个没有实际功能的常驻服务。
