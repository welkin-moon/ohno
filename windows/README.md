# Windows 10 客户端与服务

## 兼容性预检

`ohno-check.cmd` 为只读系统检查脚本，无需 .NET，也不主动请求管理员权限，可先在测试机双击查看系统版本、架构、BFE/防火墙状态与基础工具。

## 原生架构

客户端全部采用 C++17 与原生 Win32 API 编写，按 `/MT` 静态链接运行库，目标机**不需要 Python、.NET 或 VC++ 再发行包**：

- `ohno-service.exe`（固定 SCM 宿主，服务名 `Ohno`，安装于 `C:\Program Files\Ohno`）：管理单一受控工作进程树（Win10 Job Object）、持久更新事务与健康提交。
- `ohno-worker.exe`（可替换版本化工作进程）：负责向教师端注册、轮询策略、多维进程特征识别（PE `VersionInfo` / Authenticode 签名者 / 窗口标题 / 哈希 / 文件名）与黑白名单双模式、Edge 黑/白名单策略、实验性 WFP 出站限制、托管 `ohno-tun.exe`（sing-box 1.14.4 + Wintun，支持黑/白名单路由）以及 `LocalSystem` 属主命名管道。
- `ohno-request-launcher.exe` / `ohno-request.exe`：只读读取 `last_good` 版本并验证完整性后启动学生申请/课堂 PIN 窗口，后台线程执行可取消命名管道 I/O。
- `ohno-maintenance.exe` / `ohno-setup.exe`：PerMonitorV2 高分屏原生 Win32 安装与卸载向导。支持输入教师端 IP 自动拉取证书并展示 SHA-256 指纹，同窗口在线校验维护密码；已安装时双击可直接卸载；离线或故障时，提权 OS 管理员可显式运行 `ohno-setup.exe --admin-recovery-remove`。

## 构建与打包顺序

完整构建顺序见 [`.github/workflows/release.yml`](../.github/workflows/release.yml)：

1. 编译原生 Go 打包器 `ohno-pkg.exe`（`go build ./cmd/ohno-pkg`）。
2. 使用 MSVC 编译 `ohno-service.exe`、`ohno-worker.exe`、`ohno-request.exe`、`ohno-maintenance.exe`、`ohno-request-launcher.exe`。
3. 运行 `ohno-pkg.exe --version <VERSION> --directory . --output ohno-initial.ohno` 生成初始固定格式包。
4. 通过 `rc` 与 MSVC 将 `ohno-service.exe`、`ohno-request-launcher.exe` 和 `ohno-initial.ohno` 嵌入单文件 `ohno-setup.exe`。
5. 将 `ohno-setup.exe` 复制到 `teacher/embedded/ohno-setup.exe` 并使用 `go build -tags embed_setup ./cmd/ohno-teacher` 生成内嵌学生安装器的单文件 `ohno-teacher.exe`。

## 安全与部署说明

- 新安装仅在应用内固定教师公开证书（`TeacherCertificatePem`）与本校发布公钥（`ReleasePublicKey`），不再向整机 Root 证书存储新增根证书；卸载仍兼容清理旧版记录的 `ImportedRootSha1`。
- 从旧版 `OhnoPrototype` 迁移前请先卸载旧服务，再安装新版 `Ohno`。
- 在真实教室镜像分发前，请按 [隔离试用指南](../docs/trial-guide.md) 在目标硬件与 OEM 镜像环境完成实测。
