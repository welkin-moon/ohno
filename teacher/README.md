# ohno 教师端（开发中）

此服务是可运行的教师端原型，不是完整 ohno，学生端目前尚未接入。提供教师登录、批准设备、编辑域名/程序哈希规则、审核来自已批准设备的请求和限时授权。服务要求 HTTPS，登录密码以 PBKDF2 哈希保存，设备令牌只存哈希；不存在预置密码。

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
