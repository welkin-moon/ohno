# ohno 教师端（开发中）


当前教师端已经接入学生客户端。管理面和设备 API 明确分离：

- 本机管理：`http://127.0.0.1:8765`，只监听 loopback，无登录密码；用随机 CSRF token 防止浏览器跨站盲提交。
- 学生 API：`https://<teacher-host>:8443`，局域网可达，只提供注册、策略、申请和可选 PIN 解锁 API，不暴露教师管理页面。

Windows 双击 `ohno-teacher.exe` 后会自动初始化状态与 HTTPS 证书、启动两个监听口，并打开本机管理页。教师在页面中直接管理规则、批准设备、审核申请和下载本校专属 `Ohno-School-Setup.exe`，不需要记任何后台密码。

学生端现场临时解锁是独立的可选功能：教师可以在本机管理页设置 4–8 位数字 PIN；默认关闭。PIN 只用于学生机暂停限制 1 小时，采用盐化 PBKDF2 哈希保存，并有失败频率限制；它不是后台登录凭据。

教师电脑需让 TCP 8443 对学生网段可达，并保证主机名可解析。8765 只绑定 127.0.0.1，不应配置端口映射或防火墙放行到局域网。

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
