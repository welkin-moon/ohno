# Windows 10 兼容性检查与服务骨架

## 先在一台测试机检查

`ohno-check.cmd` 是只读检查，运行不需要 .NET，也不主动请求管理员权限。它查询系统版本、架构、BFE/防火墙等服务和常见系统工具，不会更改系统设置。请从资源管理器双击运行并提供窗口输出。它不能证明所有 WFP 接口可用、网络驱动兼容或后续安装一定成功。`where` 不可用时检查结果可能不准确。出于隐私，它不主动读取账号名、IP 或个人文件。

## 服务骨架

`service.cpp` 是原生 Win32 单服务的生命周期骨架：接收 SCM 启动、停止和关机消息。目前支持向教师端注册和轮询规则，仅有按文件名或哈希定期扫描并尝试终止进程的试验性拦截（并非启动前拦截），没有学生端教师密码验证；安装和服务崩溃恢复仅有试验性实现，也不能作为成品部署。

在仓库根目录的 Visual Studio x64 开发者命令行中，使用 Windows SDK 编译：

```
cl /utf-8 /std:c++17 /EHsc /W4 /MT /DUNICODE /D_UNICODE windows\service.cpp windows\agent.cpp windows\monitor.cpp windows\browser_policy.cpp src\policy.cpp /Fe:ohno-service-prototype.exe advapi32.lib winhttp.lib bcrypt.lib wtsapi32.lib
```

构建需要编译器及 SDK，成品运行时按 `/MT` 静态链接 C/C++ 运行库，不需要另装 .NET 或 Visual C++ 再发行包。精简系统可能缺失 Windows 自身的基础组件，必须通过实机检查和测试。

安装器仅供隔离环境试验，不能用于真实教室镜像。

服务从注册表 `HKLM\SOFTWARE\Ohno` 的字符串值 `ServerUrl` 读取教师端 HTTPS 根地址，使用系统证书信任链；设备凭据在本机系统注册表生成，教师批准后开始轮询。原型会在硬件 SMBIOS UUID 改变时重建设备凭据并请求审批；UUID 不存在时拒绝注册。尚未验证兆芯机器的 UUID 是否存在且唯一，因此仍不能用于实际镜像分发。

进程检测存在启动后至扫描前的时间窗口，拒绝执行可能失败，不能作为恶意程序防护。网站规则通过 Edge 的 URLBlocklist 试验性应用，只覆盖受此策略管理的 Edge；不会显示自定义提示或生成网页申请。来源联网和本地 HTML 的拦截尚未实现。

## 安装器试验代码

`setup.cpp` 和 `setup.rc` 可将服务嵌入一个原生安装程序。实验参数：`ohno-setup.exe --install https://teacher.example:8443 --certificate cert.pem`（自签证书）或省略 `--certificate`（证书已受信任）；移除：`ohno-setup.exe --remove`。程序要求管理员权限、创建自动启动服务并设置有限的 SCM 崩溃重启。指定 `--certificate` 会把所提供的自签证书加入计算机根证书存储，影响全系统的信任范围；只应在学校 IT 核验证书后使用。卸载时只移除由安装器新增的证书。当前只适用于构建与隔离测试，尚未验证完整卸载、镜像分发和学校实际环境。

策略在成功下载后缓存在受限注册表中；服务器离线时尝试继续执行缓存规则，但不沿用临时放行。若设备身份因硬件变化重建，会先清除本程序记录的 Edge 规则和缓存。断网期间的游戏申请只暂存在内存，重启服务后可能丢失。该机制尚需完整集成测试。
