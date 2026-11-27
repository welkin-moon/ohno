# ohno v1.0.0

v1.0.0 将教师端、打包工具与完整测试套件全面重构为纯原生 Go 1.24（零第三方 Go 依赖、零 Python、零 PyInstaller），并与原生 C++17 Win32 客户端打包为正式发行版。

## 主要变化

- **彻底移除 Python 与 PyInstaller**：教师端 (`ohno-teacher.exe` / `ohno-teacher`) 与更新包构建工具 (`ohno-pkg`) 均由纯 Go 标准库原生编译，启动无需解包临时目录、不依赖外部运行库或 Python 生态。
- **教师端内置学生安装器**：Windows 发行版 `ohno-teacher.exe` 通过 `//go:embed` 直接内嵌 `ohno-setup.exe` 与前端脚本，双击即可自动初始化证书与状态、打开本地 `http://127.0.0.1:8765` 管理页并生成本校专属 `Ohno-School-Setup.exe`。
- **完整托管升级与维护授权**：
  - 安装 / 卸载采用独立教师维护密码（PBKDF2-HMAC-SHA256 600,000 轮）并通过同连接 TLS-before-secret 校验，维护密码绝不写入安装包或镜像。
  - 新安装仅在应用内固定教师公开证书与本校 P-256 发布公钥，不再向整机 Root 证书库新增信任。
  - 单一 SCM 服务 `Ohno`（目录 `C:\Program Files\Ohno`）采用不可变版本目录、持久事务日志与私有健康管道提交，异常自动回滚且不降低防重放序号。
- **跨平台教师端发行**：除 Windows x64 `ohno-teacher.exe` 与 `ohno-setup.exe` 外，同步提供 Linux x64 静态可执行文件 `ohno-teacher-linux-amd64.tar.gz`。
- **请求/PIN 窗口体验与安全加固**：连接命名管道前验证 LocalSystem 属主；管道 I/O 在后台线程执行，支持取消、超时和快速关闭，窗口不卡死。

## 发行附件

- `ohno-teacher.exe`：Windows x64 教师端单文件可执行程序（内嵌 `ohno-setup.exe`）
- `ohno-setup.exe`：Windows x64 公版学生端安装程序
- `ohno-update-windows-x64.ohno`：固定格式 x64 更新包（供教师端本地验证并签名批准）
- `ohno-client-windows-x64.zip` / `ohno-teacher-windows-x64.zip` / `ohno-teacher-linux-amd64.tar.gz`：含许可证与使用指南的完整发行压缩包
- `SHA256SUMS`：全部附件的 SHA-256 校验文件

## 升级与部署提醒

- 从旧版 `v0.1.0-alpha.x` 迁移时，学生机需先卸载旧 `OhnoPrototype` 服务，再安装本版 `Ohno`；教师端原有 `OhnoTeacher` 状态与证书可继续沿用。
- 本版已在 Linux / Windows CI 通过单元测试、Go/C++ 包解析一致性、WFP、Edge 策略、命名管道、安装/卸载、托管升级与失败回滚全链测试。若部署到精简 Windows 10、兆芯硬件或 OEM 增量镜像环境，仍建议先在可恢复测试机完成现场验证。
