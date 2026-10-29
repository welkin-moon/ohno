# ohno 教师端（开发中）

此服务是可运行的教师端原型，不是完整 ohno，学生端目前尚未接入。提供教师登录、按 MAC 绑定批准设备、展示最近 DHCP IP（仅作诊断）、编辑域名/程序哈希规则、审核来自已批准设备的请求和限时授权。MAC 更换或碰撞需要人工确认；设备 ID/独立密钥才是实际认证材料，MAC 可伪造。服务要求 HTTPS，登录密码以 PBKDF2 哈希保存，设备令牌只存哈希；不存在预置密码。

## 教师端直接双击（无需命令）

Windows 双击 `ohno-teacher.exe`，首次自动在当前用户的 `LocalAppData/OhnoTeacher` 创建受限数据、HTTPS 证书和随机教师密码。密码只显示一次，请记录。浏览器自动打开 Web 管理页面，首次浏览自签 HTTPS 可能有安全警告；请验证是你自己的学校教师服务器。教师端持续监听 TCP 8443，需允许局域网连接，关闭该程序就会停止服务器，不会未经许可注册开机自启。

教师登录 Web 后点“下载 Ohno-School-Setup.exe”，得到已经写入本校 HTTPS 地址和公开证书的单文件安装包。复制到学生 Windows 10 测试机双击，允许一次 UAC 后自动安装服务。安装器**不会包含教师密码或私钥**；学生仍需教师网页批准 MAC 绑定。

教师电脑需有稳定、局域网可解析的 Windows 主机名；设备 IP 可以由 DHCP 分配，但若电脑名无法解析，学生端无法连接。学校需要固定 DNS 记录或为证书使用受管理域名。学生机安装教师自签证书会改变 Windows 计算机证书信任根，必须由学校 IT 核实。CLI 方式仍保留供进阶操作和调试。

从源码运行需要 Python 3.10+ 和 requirements.txt 中的 cryptography。Windows 原型已验证可打包为单文件程序，目标机器无需另装 Python。

初始化与运行：

```
python -m pip install -r requirements.txt
python server.py --generate-certificate --host teacher.example --cert cert.pem --key key.pem
python server.py --state state.json --init
python server.py --state state.json --cert cert.pem --key key.pem --bind 127.0.0.1 --port 8443
```

可用上述命令生成自签证书，主机名须与客户端连接地址相符；学生端仍必须信任该证书。将自签证书加入系统信任会影响整台机器的信任范围，部署前须由学校 IT 审核，私钥只留在教师服务器。`state.json` 和私钥须只允许服务管理员读取，备份时同样保护。默认只监听本机；需要在局域网访问时，明确设置 `--bind`，并限制防火墙访问范围。不要将状态或密钥提交到仓库。

API 文档尚在开发中；单元和集成测试通过 `python -m unittest discover -s teacher` 运行。尚未验证并发压力、Windows 打包及全部安全边界，不要在真实学校环境部署。
