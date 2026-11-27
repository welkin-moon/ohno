# ohno v1.1.0

v1.1.0 全面重构学生机安装体验与教师端局域网部署流程，并新增**可执行文件多维特征识别（防改名）**与**网站/程序黑名单・白名单双模式**。

## 主要变化

### 1. 安装流程与界面全面重做
- **自动包含局域网 IP 的 HTTPS 证书**：`ohno-teacher.exe` 首次启动自动识别本机局域网 IPv4 并写入证书 SAN；支持在教师页一键重新签发含最新局域网 IP 的证书并热重载 HTTPS，解决按 IP 连接报证书错误的问题。
- **免找 `.pem` 文件的单窗口现代向导**：
  - 安装器新增 Common Controls v6 与 PerMonitorV2 高分屏 DPI 适配，采用系统清晰字体，彻底告别模糊旧式弹窗。
  - 运行通用 `ohno-setup.exe` 时，只需输入教师端 IP（如 `10.181.203.70`，自动补全 `https://` 与 `:8443`）并点击「连接教师端」，即可通过 `/api/bootstrap` 自动拉取并校验服务端证书、展示 SHA-256 短指纹供教师核对，并在同一窗口输入维护密码完成一键安装。
  - 教师端首页提供「学生机快速部署（3 步完成）」卡片，支持按局域网 IP 下拉生成专属 `Ohno-School-Setup.exe`、一键下载公开证书、展示证书指纹与放行 8443 端口的防火墙命令，且首次初始化自动建立本校发布信任。
  - 安装失败提示明确区分网络不可达、证书不匹配、维护密码未设置或错误等原因；已安装环境下双击安装器可直接选择卸载。

### 2. 程序多维特征识别（防改名）
- 除文件名与 SHA-256 外，Windows 监控引擎新增原生 PE `VersionInfo`（`OriginalFilename` / `InternalName` / `ProductName` / `FileDescription` / `CompanyName`）、Authenticode 数字签名发布者以及可见顶层窗口标题提取。
- 支持前缀化特征规则：`orig:`、`product:`、`company:`、`desc:`、`signer:`、`title:`、`path:` 及全字段匹配（不区分大小写、支持中文），即使学生将游戏 `.exe` 改名为 `word.exe` 或 `notepad.exe` 仍能准确识别拦截。
- 教师端审批列表展示丰富程序标识（例如 `word.exe (Plants vs. Zombies)`），便于教师识别伪装程序。

### 3. 网站与程序黑名单 / 白名单双模式
- **网站双模式**：支持独立切换**黑名单模式**（默认放行，仅拦截黑名单域名）与**白名单模式**（Edge `URLBlocklist = ["*"]` + `URLAllowlist`，且 `sing-box` TUN 保持 DNS 放行、仅放行白名单后缀与临时批准域名、拦截其余 80/443 流量）。
- **程序双模式**：支持独立切换**黑名单模式**与**白名单模式**（仅放行 Windows 系统目录、Session-0 系统服务、Ohno 自身及白名单文件名/哈希/特征规则命中的程序，防止误杀系统进程）。
- **审批一键加白**：教师端审批请求新增「永久加入白名单」按钮，可直接将学生申请的网站或程序哈希写入永久白名单并立即推送新策略。

## 发行附件

- `ohno-teacher.exe`：Windows x64 教师端单文件可执行程序（内嵌 `ohno-setup.exe`）
- `ohno-setup.exe`：Windows x64 公版学生端安装程序
- `ohno-update-windows-x64.ohno`：固定格式 x64 更新包（供教师端本地验证并签名批准）
- `ohno-client-windows-x64.zip` / `ohno-teacher-windows-x64.zip` / `ohno-teacher-linux-amd64.tar.gz`：含许可证与使用指南的完整发行压缩包
- `SHA256SUMS`：全部附件的 SHA-256 校验文件

## 升级与验证说明

- 与 v1.0.0 的 `state.json` 及策略协议完全向后兼容；已有教师机如旧证书缺少局域网 IP，可在教师页点击「一键重新签发含当前局域网 IP 的证书」。
- 本版已在 Linux / Windows CI 通过全部零 Python 守卫、C++17 特征匹配与双模式策略测试、`sing-box` 黑/白名单配置校验、Go 教师端竞态测试、WFP、Edge 策略、命名管道、安装/卸载与托管升级端到端验证。部署到精简 Windows 10、兆芯实机或 OEM 增量镜像前仍建议先在可恢复测试机现场实测。
