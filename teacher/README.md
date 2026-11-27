# ohno 教师端（Go 原生实现）

教师端使用 Go 1.24 标准库编写，零第三方依赖、零 Python 运行时，编译为单文件原生可执行程序（Windows `ohno-teacher.exe` / Linux `ohno-teacher`）。

管理面与学生 API 严格分离：

- **本机管理**：`http://127.0.0.1:8765`，仅监听 loopback 并校验 `Host` 头，无登录密码，使用随机 CSRF token 防止跨站提交。
- **学生 API**：`https://<teacher-host>:8443`，局域网可达，仅提供设备注册、策略、申请、可选 PIN 解锁、维护授权与托管升级 API，不暴露管理页面。

## 直接运行

Windows 发行版 `ohno-teacher.exe` 已内嵌 `ohno-setup.exe` 与 `update_ui.js`，双击即可自动在 `%LOCALAPPDATA%\OhnoTeacher` 初始化证书和 `state.json` 并打开浏览器管理页。

命令行显式运行（Windows / Linux 通用）：

```bash
go build -o ohno-teacher ./cmd/ohno-teacher
./ohno-teacher --generate-certificate --host teacher.example --cert cert.pem --key key.pem
./ohno-teacher --state state.json --init
./ohno-teacher --state state.json --cert cert.pem --key key.pem --bind 0.0.0.0 --port 8443 --control-port 8765 --host teacher.example
```

## 维护授权与发布信任

- **教师维护密码**：仅用于学生机正常安装/卸载（PBKDF2-HMAC-SHA256 600,000 轮），与日常管理、镜像开机及可选 4–8 位课堂 PIN 完全分离。
- **本校发布信任**：在本地页面点击“初始化本校发布信任”，在状态文件旁创建受保护的 `<状态名>.releases` 目录（POSIX `0700` / Windows 受保护 DACL 仅允许当前用户、SYSTEM 与 Administrators）并生成独立 P-256 签名密钥。
- **包构建器**：使用 `go build ./cmd/ohno-pkg` 编译 `ohno-pkg`，构建未签名的 `OHNOPK01` 更新包，随后在教师端页面验证并签名批准。

## 测试

```bash
go test -race -v ./teacher/...
```
