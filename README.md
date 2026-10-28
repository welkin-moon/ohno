# ohno — 课堂助手（策略核心原型）

> **当前仅为策略模拟器，不是可安装产品。** 有未完成的单服务与教师端原型；没有 TUN、过滤驱动或安装程序；程序哈希限制仅为轮询终止进程的试验功能，无法可靠拦截执行。不要用于管理真实课堂电脑。

## 已实现

C++17 策略决策代码，以程序输入模拟以下情形：

- 按规范化域名精确或包含子域名匹配；阻止与请求审批是一项决策，具体阻断由将来的执行层实现。
- 按 SHA-256 匹配应用；不使用 `javaw.exe` 等共享运行时的文件名作为游戏标识。
- 来源为下载、可移动介质、未知的程序联网请求要求审批；受管理来源默认允许。
- 本地 HTML 访问默认可设为请求审批（模拟）。
- 授权绑定设备、用户、对象和操作类型，并有到期时间。此处仅是内存中的比较逻辑，**没有签名、登录、审批服务或持久化**。

示例域名 `game.example` 和哈希均为占位演示数据，**不是实际游戏拦截列表**。

## 构建与测试

Linux/macOS 安装 C++17 编译器和 make 后：

```sh
make test
make
./ohno-sim
```

Windows 上可用 Visual Studio 的 x64 Native Tools 命令提示符构建模拟器，使用静态 CRT：

```bat
cl /std:c++17 /EHsc /W4 /MT /Isrc src\main.cpp src\policy.cpp /Fe:ohno-sim.exe
cl /std:c++17 /EHsc /W4 /MT /Isrc tests\policy_test.cpp src\policy.cpp /Fe:policy-test.exe
policy-test.exe
ohno-sim.exe
```

这只构建模拟器；不需要在目标机器安装 C++ 运行库。Windows 构建命令尚未在 Windows 上验证。`/MT` 不等于可以在任何 Windows 版本上运行，目标系统和 SDK 仍需匹配。

## 决策接口契约

调用方必须从可信系统渠道获取机器、用户、操作类型、对象及文件来源。域名须由可信调用方规范化为小写 ASCII A-label，去掉末尾根点；对象哈希须由可信执行层计算、使用小写十六进制。非法输入返回阻止。程序不负责 IDNA 转换、计算哈希、认证或保护传入的数据。

授权必须按用户、机器、对象、类型精确匹配，当前时间严格小于到期时间。对象发生变化则不自动沿用授权。当前未实现完整应用身份：Java/启动器、脚本、进程树和浏览器网页等不能简单用一个可执行文件哈希代表，详见 `docs/design.md`。

## 文档

- `docs/design.md`：Windows 端、教师端、安装与镜像分发、故障恢复、已知边界和后续验收。
- `docs/open-questions.md`：实现前需要确认的学校环境。

- `windows/ohno-check.cmd`：目标 Windows 机器只读兼容性检查。
- `windows/service.cpp`：原生 Windows 单服务骨架和教师端注册/策略轮询，未实现拦截；尚未完成 Windows 实机验证。
- `docs/decisions-2026-10-28.md`：根据已确认的兆芯机器、Windows 10、管理员与教师内网服务器更新的设计。

- `teacher/`：教师端 HTTPS 登录、设备审核、规则和临时批准原型；需要 Python 构建打包成免安装版本，尚未部署。
