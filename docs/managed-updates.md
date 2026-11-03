# 托管升级与教师维护授权

状态：当前源码包含教师维护授权、原生受管安装、教师签名批准目录、拉取暂存、单一 SCM 宿主、持久切换与失败回滚。**这是开发预览，不是已通过目标教室硬件验收的成品；已发布 alpha.6 不包含这些新增功能。** 以下按实现顺序说明各组件，集成行为见文末；只有相应提交的 Windows CI 全绿才代表该提交通过隔离测试，不能用单组件校验代替整链验收。跟踪：[Issue #7](https://github.com/welkin-moon/ohno/issues/7)。

## 用户要求与现有行为

目标是 Windows 10 x64 的原生自包含客户端，无 .NET 依赖；管理员在模板机安装一次，再经 OEM 镜像分发。服务既保活，也拉取教师端已批准的构建。教师本机 Web 管理页继续只监听 loopback，并且免后台登录；日常策略审批不新增密码步骤。

“添加”暂按新增客户端 / 安装入口解释，而不是所有教师操作。现在代码有三个不同步骤：安装、设备登记、教师批准设备。当前源码的正常安装 / 卸载使用独立的教师维护密码，**不复用短课堂 PIN**。镜像分发后的启动不弹安装向导，不重复输入维护密码；这并不等同于自动信任所有新设备。

镜像中的教师 HTTPS origin、公开证书、发布验证公钥与学校配置可以复用；教师密码、其可离线破解的验证数据、服务器私钥、可复用安装授权和同一设备身份不得随镜像传播。保留现有 MAC + SMBIOS 硬件锚变化后的每机随机 ID / 密钥重新生成逻辑，继续独立登记及教师批准。MAC 只是关联信号，不是认证秘密。首次模板安装应在封装前清除实例身份/临时授权；分发后生成每机身份，不要求每台重新安装。

系统管理员始终可通过 Windows 标准服务管理、恢复和移除手段处理故障。维护密码约束产品正常入口，不是对抗 OS 管理员的安全边界。正常停止和卸载不触发重新安装；不隐藏服务、不干扰安全工具、不增加互相复活的服务或驱动。

## 第一阶段：已实现的纯校验组件

- `teacher/update_manifest.py`：签名、严格解析、验签及新版本资格检查。只提供函数，不创建密钥，不监听 API，不导入/批准构建，不下载或执行内容。
- `src/update_manifest.hpp`：与 Python 一致的有界格式、签名原文、版本/期限/防重放规则。解析本身不等于认证。
- `windows/update_verify.cpp`：使用系统 CNG 的 ECDSA P-256 / SHA-256 公钥验签；`verify_update_offer()` 同时检查格式、签名、序号、时间和兼容版本，无文件或服务副作用，不需要外部运行时。
- Python、跨平台 C++、Windows CNG 共用一个只有公钥与签名的测试向量，覆盖篡改、错误公钥、整数范围、重复键、未知字段、路径注入、过期、时钟偏差和版本重放。

### 格式 v1

JSON 必须恰好包含以下 10 个字段。任何未知或重复字段、浮点/指数数字、bool 代整数、超长 JSON（4096 字节上限）均拒绝。使用 UTF-8；不接受 UTF-16/32 或 BOM。

| 字段 | 约束 |
| --- | --- |
| `schema` | 整数 `1` |
| `platform` | 精确 `windows-x64` |
| `sequence` | 正整数，最大 `2^53 - 1`；教师发布的单调序号 |
| `version` | 受限 ASCII 显示版本，例如 `0.2.0-alpha.1`；不用于新旧比较 |
| `min_updater` | 1–65535 的协议执行器版本；过旧客户端失败关闭 |
| `issued_at` / `expires_at` | 整数 Unix 秒；有效期大于 0 且不超过 7 天；最多容忍签发时间在未来 300 秒 |
| `size` | 精确安装包长度，1024–268435456 字节 |
| `sha256` | 64 位小写十六进制的完整包 SHA-256 |
| `signature` | P-256 ECDSA `r || s`，每项 32 字节的大端值，共 128 位小写十六进制 |

签名原文是 ASCII：域分隔行 `ohno-update-p256-sha256-v1`，随后依次为 schema、platform、sequence、version、min_updater、issued_at、expires_at、size、sha256；每项以 LF 结尾，包括最后一项。JSON 的空格、字段顺序不参与签名。签名域禁止换行，消除拼接歧义。

验证公钥采用 SEC1 非压缩 P-256 点（`04 || X || Y`，130 位小写十六进制），由安装时已核实的学校信任配置提供；清单不能自行提供公钥或要求信任新键。发布签名密钥与教师 HTTPS 私钥分离，只保留在教师端受限状态目录。发布身份生成、持久化与安装时绑定见下文；自动信任轮换尚未实现。缺少可信公钥必须拒绝升级，不回退为“只有哈希”校验。

包的路径由摘要生成：`/api/device/update/package/<sha256>`。清单没有任意 URL、命令行、目标路径或解压条目。原生下载器固定安装时的 HTTPS origin、禁用重定向、正常验证 TLS，并再次核对最终字节数与哈希。签名验证先于下载；完整包验证先于执行；来自同一次未经认证下载的 SHA256SUMS 不能代替发布签名。

## 第二阶段：服务端维护授权

教师本机控制台新增维护密码设置 / 停用，仍不需要后台登录。使用 PBKDF2-HMAC-SHA256 600,000 轮、每次随机 16 字节盐；密码为 12–128 字符的 UTF-8 口令，仅在教师端保存验证记录，与课堂 PIN 完全分离。依据 [OWASP 的 PBKDF2 工作因子建议](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2)；没有声称此参数使程序或运行环境获得 FIPS 认证。

- 局域网 HTTPS `POST /api/maintenance/authorize` 安装只接受 `action`（install）、客户端随机 32 字节 nonce 的 64 位十六进制表示、`maintenance_password`；卸载可另带 `device_id` / `device_key`。UTF-8 JSON 限 2048 字节，拒绝未知字段与重复键。
- 安装授权要求正确的教师维护密码。卸载还要求现有设备 ID / 密钥（新版原生客户端放在 TLS 验证后的 JSON 正文；为兼容旧 API 允许 `X-Ohno-Device` / `X-Ohno-Key`，但正文与 Header 不可混用）；待审批或已停用的设备仍可用真实密钥卸载，避免撤销审批造成无法正常卸载。
- 返回通过 HTTPS 直接认证的短时决定，包含 action、nonce、device_id、authorized_at、expires_at（120 秒），**不是可复制的 bearer token 或离线票据**。安装器检查这些值与本地随机事务匹配并立即使用；不写入模板或用于克隆首次开机。此端点不会执行任何客户端操作。
- 全局每 300 秒最多 32 次 KDF，单来源最多 8 次，包括成功请求；最多两个并发 KDF，且不在教师策略锁内计算。来源地址来自连接，不信任转发 Header。限流记录有界，不随任意来源无限增长。LAN 洪泛可能暂时阻止维护，但不占满策略 worker；OS 管理员恢复通道不受其约束。
- 密码被关闭/轮换时，进行中的旧密码校验失效。成功决定先记录最近 100 条不含密码或设备密钥的事件再返回；状态保存失败返回 503，不产生未落盘授权。
- 未设置密码默认拒绝维护 API，停用密码也拒绝而不是放行。不会影响已有注册、心跳、日常审批或镜像唯一身份逻辑。学校安装包携带 origin、公开证书及已初始化的发布验证公钥；不携带维护密码、验证哈希或私钥。

### 第三阶段：原生安装 / 卸载入口

- 新版 `ohno-setup.exe` / 学校专属包显示 Win32 密码框，支持关闭、取消和重新尝试。没有 .NET 依赖。教师密码不通过命令参数或环境变量传递；隔离自动化可显式使用 `--password-stdin` 读取一行 UTF-8。临时自有密码缓冲区使用后清零，密码不持久化。
- `maintenance_http.cpp` 在**实际发送请求的同一 TLS 连接**先核实证书，后写入含密码 / 设备密钥的正文。提供学校公开证书时只容忍 unknown-CA，并要求完整叶证书 DER 精确匹配；域名、期限和用途验证仍生效。没有 pin 时使用正常系统信任链。当前新安装全程不导入整机根证书；授权前不改文件、注册表或服务。
- 只使用固定 HTTPS origin 与固定授权路径，禁止 HTTP、跳转、代理、Cookie、自动 Windows 凭据、HTTP 自动重发。最多尝试同主机两个 IP 地址（仅连接阶段）；5 秒网络超时，20 秒单次单调时钟截止；响应 2048 字节、Header 8192 字节上限。校验 action、随机 nonce、device ID、120 秒期限；允许 30 秒教师 / 客户端时钟偏差，不产生可离线复用许可。
- 失败、断网、密码停用、证书错、nonce 错均拒绝且不开始系统变更。正确授权后才继续原有安装流程，并保存服务器地址与**公开**证书。学生机身份在服务首次运行时独立生成，镜像启动仍不弹安装密码框。
- Windows 应用列表注册 `ohno-maintenance.exe --remove`；正常卸载在线验证教师密码和该设备密钥。待审批或撤销设备仍能正常授权卸载。服务尚未登记、教师失联或配置损坏时，**提权 OS 管理员**可显式运行 `ohno-setup.exe --admin-recovery-remove`，使用同一清理流程而不冒充教师授权。
- 不隐藏服务，不阻止管理员标准恢复。卸载正在运行的维护器自身时，用标准重启后删除机制仅安排删除该文件，并提示剩余目录需检查；不会递归删除未知内容。CLI 测试使用外部安装器，尚未验证 GUI 应用列表卸载后的真实重启清理。
- Windows CI 使用临时证书 / 密钥与隔离 runner，覆盖原生传输、错误授权零副作用、取消 / 重试 / 重复点击，以及实际安装、教师撤销和正常卸载。Linux 可运行 fixture 自测，但不能替代 Windows 原生执行结果。仍需授权的真实 Windows 10 / OEM 镜像验证。

已发布 alpha.6 不会因为服务端设置密码就得到保护，须配套新版程序。维护授权入口本身不等于自动升级；完整发布、拉取、事务与服务集成见下文。

## 持久事务组件

`src/update_transaction.hpp` 定义严格的 `stable → prepared → probation → stable` 事务记录。`prepared` 保留旧活动版本；只有原子持久化 `probation` 后才允许启动候选。健康证明必须匹配本次随机事务 ID、序号、版本、包摘要和成功的 agent 工作周期，不能使用联网成功或 SCM RUNNING 代替。进程 / 系统重启遇到任何未提交状态，先持久化回滚到 `last_good`；防重放高水位不降低。失败构建不可循环重试，重新发布旧字节也必须使用更高序号。

`windows/update_journal.cpp` 为已有的可信、权限受限本地 NTFS 目录提供文件存储：全程独占安装锁，拒绝 UNC、路径别名、reparse point 与文件硬链接，持有祖先目录句柄防止中途改名。新记录写到同目录固定暂存文件，显式 FlushFileBuffers 后通过不允许跨卷复制的 write-through rename 切换，再 flush 选择记录。写结果不确定时禁用当前 storage 实例，调用者必须重开并恢复，不能乐观执行。缺失 / 损坏记录失败关闭，不能自动从旧备份降低高水位；初始化仅限显式安装，不覆盖现有状态。

单元测试在每个状态边界注入“未写入 / 已写入但结果不确定”，Windows CI 在实际半写、flush 和 rename 的 7 个检查点强制退出独立进程，再重新打开恢复（35 个中断组合），另测独占锁、损坏、旧暂存文件、硬链接和只读磁盘错误。仅使用临时目录，不安装服务、不创建发布密钥。这验证了进程中断恢复，**不等于目标硬件突然断电的验证**；存储设备仍须正确执行 Windows flush / write-through。

这个纯事务组件不负责下载、解包或启动候选；包验证、受保护版本目录、教师当前批准复查与私有健康通道由下面的组件和服务运行时组合完成。

## 固定包与教师批准目录

`teacher/update_package.py` / `src/update_package.hpp` 共用 `OHNOPK01` 无压缩容器：8 字节 magic、LE16 版本长度 / 文件数、6 个 LE64 文件长度，随后 ASCII 版本和固定顺序文件。仅包含 worker、申请 UI、维护器、TUN 及两个许可证；没有可指定的路径、命令、链接或可替换服务宿主。前四个文件要求 x64 PE32+，总体不超过 256 MiB，所有长度精确相加且无尾部数据。包外层仍必须通过已经固定学校公钥的签名清单与完整哈希校验；仅解析成功不是认证。

教师本机 CSRF 保护的页面提供显式初始化独立发布身份、验证并批准本地包、暂停发布。私钥只在教师状态旁受限目录，不进入 HTTP 响应或包；新目录在 POSIX 使用 0700，在 Windows 创建时即附加受保护 DACL（仅当前教师账户、SYSTEM、Administrators），不修改已有目录权限；全程文件锁防止多个进程并发分配序号。先写入不可变 SHA256 命名包，再原子保存带签名的批准与高水位；存储结果不确定时毒化实例，须重启检查，不能从旧内存继续放行。重启遇到残缺私钥 / 签名状态不自动重新生成身份。

API 使用 POST 正文传设备秘密，供原生客户端在实际 TLS 验证后发送：`/api/device/update/offer`、`/api/device/update/package/<sha256>`、`/api/device/update/authorize`。设备需已经批准、真实密钥有效且 MAC 仍绑定；只返回当前批准的摘要。执行许可还校验清单序号 / 摘要，并返回随机 nonce、设备、120 秒期限；不是离线票据。暂停发布、设备撤销、MAC 变化、已过期或旧批准均拒绝。原生服务在完整下载与验证后、切换前再次调用执行许可。

上传脚本只从本机同源加载，不接第三方资源。重复点击只发一次，取消 / 导航中断会明确提示结果未确认，要求刷新再决定重试或暂停；不会把断网错误当作服务器未持久化。已有纯 C++ / Python 共同畸形包测试、教师 API 集成与脚本中断状态测试。没有真实学校发布密钥或现场推送。

## 原生拉取与隔离暂存

学校安装包 v2 `OHNOBT02` 在公开 HTTPS 证书外固定 130 字符 SEC1 发布公钥。教师端仅从本校已初始化的发布身份写入该公钥；安装器在正常维护授权成功后保存。旧 v1 / 未初始化教师发布身份仍可安装，但没有可信发布公钥就关闭自动更新，不从清单自学信任，不复制私钥或维护口令。

`trusted_post()` 复用维护授权的同连接 TLS-before-secret 路径，只允许固定 OHNO 路由；更新设备密钥仍在验 TLS 后才进入正文。清单先验固定公钥签名 / 序号 / 时间 / 平台，再创建限长下载文件；包使用流式 sink、300 秒截止、5 秒网络超时、STOP 检查、无跳转 / 代理 / 自动重发。下载完成后重新验证清单新鲜性、精确长度、整包 SHA256、x64 固定文件集与版本，之后才允许提取。

暂存只在持有安装锁的受限 NTFS 根目录下进行，源文件拒绝硬链接 / reparse point 并在映射期间禁止写 / 删除；固定文件逐个 write-through / flush，连同原始包及签名记录在独立随机 staging 目录中完成，再原子改名为 `<序号>-<摘要>` 版本目录。不会覆盖运行中的二进制，不改变活动 journal。崩溃残留只回收格式精确、带本程序所有权标记的 staging 目录和固定文件，绝不递归删除未知内容。启动前可再次比较提取文件与已认证原包；已安装版本签名仍验证，但不因发布许可过期就无法离线运行。

执行前另向教师端请求 nonce / 设备 / 序号 / 摘要 / 120 秒期限绑定的新决定，拒绝暂停、撤销或变更批准。这个函数不把决定存成离线票据，也不启动候选。Windows CI 使用临时 HTTPS / 签名密钥与目录，验证正常拉取、错误 TLS pin、错误发布 key、篡改 / 大小 / 架构 / 重放 / 跳转、取消、错 nonce / hash / device / sequence、撤销、提取文件篡改、初始 baseline、10 个真实暂存中断点及重开回收；不会执行包中 fixture 程序。这一组件测试不执行包中程序；实际启动、私有健康证明与活动切换由文末服务宿主集成测试另行验证，不能把暂存通过当作升级完成。

## 设计边界与验收门槛

### 1. 教师批准与维护密码

本机控制面先校验 Host/loopback 和 CSRF。单独设置维护密码：带随机盐的慢哈希、常量时间比较、全局 + 来源限流、有界请求和工作量，不记录密码或令牌。不要求每次打开后台登录；安装/卸载授权时验证维护密码。密码从学生机传输时只走已核实的 HTTPS；不进入参数列表、日志、学校安装包、镜像或注册表。

正常安装授权与卸载授权须为短时、用途和设备/安装事务绑定的许可，不能通过复制许可到另一台机器获得授权。不要为了让模板机离线分发而把永久学校秘密放进模板。首次模板安装和镜像启动是不同流程。

教师显式批准经版本、平台和完整性检查的不可变构建。只有现有批准且设备密钥有效的客户端可读最新清单/包；停用设备和 MAC 失配应拒绝。服务器不把 GitHub latest 自动标成已批准。发布序号及已批准包必须先原子持久化，再对设备可见；磁盘故障不得产生未落盘的有效发布。撤销/暂停发布后不再返回清单；已经下载的离线包无法靠撤销 HTTP 下载收回，因此执行前还须检查当前授权。

### 2. 持久更新事务与回滚

只保留一个标准 SCM 自启动服务。优先把稳定的服务宿主/维护器与可替换工作负载分离；不要让运行中的二进制直接覆盖自身。版本写入独立受限目录，先暂存、fsync、验证，再使用原子记录选择当前版本。服务更新须响应 STOP/SHUTDOWN，正常卸载优先，不能用保活与管理员争抢控制。

必须定义可恢复的状态机（示例：`downloaded -> verified -> switch_pending -> health_pending -> committed`，失败转 `rollback_pending -> rolled_back`）。持久事务写入与启动恢复应覆盖每个中断点；不能宣称多文件覆盖天然原子。上一已知可用版本保持只读且在新版本健康检测完成前不清理。健康证明须包含本次事务 ID、实际版本与服务正常处理能力，不能只看 SCM 的 RUNNING 状态或教师网络是否在线。

可信序号高水位需要独立持久化，成功回滚不可降低。失败的新序号被标记，避免每次启动反复失败升级；若教师确需下发旧二进制，使用更高序号重新批准相同摘要，而不是关闭防回放。时钟不可信或磁盘状态损坏时保持现有版本，报告错误，不直接执行新包。

安装器、维护器、服务、UI、TUN 和许可证必须作为兼容的一组管理。旧 alpha.6 安装器不能被假定为具备事务更新能力：当前 `--install` 会拒绝已安装服务。进入新协议前需要一次显式受控迁移，不伪装调用旧安装命令为升级。

### 3. 验收

仓库单元测试 + Windows CI 覆盖：错误签名、篡改包、重定向、错误大小、断网、磁盘满/只读、重放、错误平台、旧执行器、教师撤销、下载取消、重复并发更新、每阶段进程/系统中断、失败健康检查、回滚、安装与卸载竞争、正常停止不复活。CI 的临时测试环境不等于实机安装授权。

最后仍需经授权的可恢复 Windows 10 x64、兆芯设备、联想 OEM 镜像验证；失败可恢复、教师网络离线、多个克隆唯一身份及教学软件兼容是发布门槛。未通过前不向真实教室推送。

## Windows 平台依据

- [SCM SERVICE_FAILURE_ACTIONS](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw)：使用系统异常恢复机制，不构造隐藏保活。
- [BCryptVerifySignature](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptverifysignature)：CNG 的 ECDSA 验签输入是哈希。
- [Microsoft CNG 签名示例](https://learn.microsoft.com/en-us/windows/win32/seccng/signing-data-with-cng)：原生 API 的密钥与签名流程。

### Native host/runtime

`PayloadLayout=1` explicitly selects the managed host. An absent marker retains
existing installs; invalid markers or a missing/corrupt managed journal never
silently bootstrap a new replay floor. The managed installer integration below creates the trusted baseline and marker
after teacher authorization. Previously published installers are not retroactively
migrated by this source change.

The SCM host owns one worker process tree. It verifies retained package/signature
and every extracted file before starting the fixed `ohno-worker.exe`, uses an
explicit executable path (no shell), and inherits only a private stop event and
health-pipe writer. A non-inherited kill-on-close job is assigned atomically at CreateProcess via the Windows 10 JOB_LIST attribute and owns workers and descendants;
normal service STOP and uninstall win, and host death cannot leave an independent
watchdog/TUN tree. This uses standard Windows [handle lists](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
and [nested jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs),
not a second persistent service or protection against OS administrators.

Startup durably rolls back any incomplete transaction before launch. New builds
stage while the old worker runs, then obtain a fresh online decision before
prepare. Its in-memory launch budget is capped at 20 seconds, never persisted as
a bearer token. Old worker shutdown and confirmed whole-job drain precede durable probation and candidate
launch; a bounded drain failure exits the host instead of launching another version. Health is a bounded strict document over the inherited private pipe,
bound to the random transaction and actual launched sequence/version/hash. The
production worker reports only after a completed local policy cycle with its
request pipe, TUN and WFP operations successful; offline cached policy is allowed. A trial candidate must have applied a valid policy; stable baseline startup may still be awaiting initial/clone device approval. Mere SCM
RUNNING, a responding teacher, or a public pipe is not a health proof.

Only durable health commit changes last-good. Timeout, exit, malformed/mismatched
proof or STOP before commit terminates the candidate and rolls back without
lowering high-water. Uncertain persistence exits the host and requires journal
recovery, not optimistic continuation. Ordinary worker exits use a bounded
restart budget, then standard SCM recovery; an explicit normal STOP is not
restarted. Device identity is read after worker health, so existing hardware-bound
clone identity regeneration runs first. No maintenance password is used here.

Windows CI executes only compiled fixture workers in temporary directories for
this slice, including health refusals, current approval revocation, rollback,
replay, stop-at-boundary, nine real host process crashes (including atomic creation/pre-resume boundaries), offline committed launch,
worker keepalive and killing the host with a live descendant. Actual production worker/installer/service update acceptance is covered by the
managed integration CI described below; a source change alone is not a pass.


### Managed installer integration

The installer now explicitly creates layout 1 after online maintenance authority:
new protected Program Files directory, fixed SCM host/root maintenance entry,
read-only request launcher, an embedded baseline package and durable initial
journal. Payload creation precedes SCM startup. A separate maintenance-only build
avoids recursively embedding an installer inside its own payload. The fixed root
maintenance entry is deliberately retained for offline OS-admin recovery; it is
not overwritten by ordinary worker updates.

The request launcher pins trusted NTFS ancestors, reads an atomic selector
snapshot without the writer lock, verifies retained package bytes, and starts the
last-good version's GUI. It never runs probationary UI. Removal waits for SCM STOP
before conservative owner-marked exact-file cleanup; corrupted journals don't
block explicit administrator recovery. Unknown content/reparse/hardlinks are not
recursively deleted. New directory ACLs grant full control to SYSTEM/admins and
read/execute to ordinary users; existing machine permissions are not rewritten.

SCM non-crash failure actions are explicitly configured and read back in tests.
Microsoft documents that this [flag takes effect after a system restart](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag);
no immediate first-install guarantee is claimed. Ordinary process failure uses
standard SCM recovery. An already-signaled STOP is reported as success. Windows CI now exercises actual managed installation,
production worker update commit, signed unhealthy fixture rollback, replay floor,
standard STOP staying stopped, explicit restart, configured recovery flag plus actual process-failure recovery,
teacher-authorized removal/reinstall and offline OS-admin recovery. No production
key, actual classroom service or user machine is touched by these CI fixtures.

Non-crash recovery across reboot and full OEM image acceptance remain target-VM/hardware qualification, not a result inferred from same-boot CI.

### Additional acceptance fixtures

The next acceptance tests exercise the fixed request launcher before update, after
commit and after rollback, verifying the actual GUI executable path and normal
window close. They run in the CI runner's user session, not a separately created
standard-user account. The read/execute ACL and readonly selector tests remain
separate; this is not a claim of full standard-user desktop qualification.

A deliberately silent fixture keeps its health writer open until stopped. Both
the isolated runtime's 3-second fixture deadline and the production service's
90-second deadline are checked using elapsed time logged by that test worker;
this is distinct from an immediate EOF failure. No production timeout is shortened.

The image test changes only the ephemeral installation's stored source-hardware
anchor, restarts without an installer while maintenance authority is disabled,
and verifies new device ID/key, discarded cached policy/grants, unchanged committed
version/replay floor and ordinary separate device approval. It does not change the
runner's actual UUID/MAC, perform an OEM clone, or qualify two physical machines.
All credentials and keys belong only to the disposable CI fixture.

A future explicitly triggered release also includes `ohno-update-windows-x64.ohno`
and its SHA256SUMS entry, for teacher inspection/approval. This workflow change does
not publish a release or change VERSION; alpha.6 downloads remain unchanged.

### Native test-gate correction

Inspecting complete CI logs exposed a separate program-hash regression hidden by
`cmd`'s positive-only `if errorlevel 1`: negative abort/NTSTATUS exits could be
followed by successful commands and a green job. Every native build/test guard
now rejects both positive and negative failures, with an actual cmd subprocess
regression. Earlier green job badges alone are not evidence that hash-test passed.

`program_image_hash` no longer reuses digests across calls based solely on path,
file ID, size, mtime and ChangeTime; rapid same-size rewrites can share those time
values. It hashes current bytes under the existing writer/rename-denying handle,
retaining STOP and 512 MiB bounds and before/after checks. Thirty-two no-sleep
restored-mtime writes exercise this regression. This conservative correctness fix
may increase scanning cost; safe caching and target-hardware performance still
need separate measurement, not a weakened integrity assertion.

### Daily device transport

Registration, policy polling, requests and optional classroom-PIN unlock now use
the same native pre-body-authenticated TLS transport as maintenance/updates.
Only four fixed POST routes are added. Device keys/PIN are in the body, never
headers, URLs or command lines. The negotiated connection must pass exact leaf
pin, hostname, validity and server-usage checks before secret bytes are written;
there is no proxy, redirect, cookie, integrated authentication or body replay.
The existing 20-second aggregate / 5-second I/O bounds and STOP signal apply.

The configured PEM is public trust data. A missing pin on a legacy OS-trusted
installation retains normal OS validation; a present but empty/malformed registry
pin fails closed rather than downgrading. No new root-store or OS permissions are
changed by this transport. Policy JSON retains its existing 1 MiB bound; other
JSON routes stay limited to 8 KiB, and native inputs remain limited to 2 KiB.

The teacher supports body credentials plus legacy header clients, but rejects
mixed/partial/duplicate credentials. Approval, MAC binding, revocation and local
control-plane separation still apply. CI adds 24 real WinHTTP cases across all
four routes: valid 200/201 and large policy, wrong pin, expired/hostname-mismatched
certificate, redirect and oversize. These use only loopback listeners and short-
lived fixture secrets, no installation or trust-store changes.

### Local request/PIN pipe identity

The request window now queries the owner on the **connected pipe handle** before
writing any website/PIN bytes, and accepts only a LocalSystem-owned object.
The service explicitly assigns the pipe's creator-user SID as owner (SYSTEM in
the production worker), keeping the existing local authenticated-user DACL and
no-create-instance rights unchanged. A normal user squatting the public name
therefore cannot collect the classroom PIN; an OS administrator/SYSTEM remains
outside this boundary and retains standard recovery/removal authority.

The client requests READ_CONTROL plus individual data rights, not GENERIC_WRITE,
and uses identification-only SQOS so a squatting server cannot impersonate it for
access. See Microsoft's [named-pipe access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
and [GetSecurityInfo handle/owner requirements](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo).
No persistent account, ACL, privilege or trust-store setting is changed by this
client check; the server descriptor applies only to its newly created IPC object.

A disposable user-owned fake pipe must receive zero PIN bytes and return the
explicit untrusted result; input buffers are erased on refusal and absence.
The E2E driver shares the GUI's exact client implementation for real SYSTEM-service
website requests and PIN unlock, with retries only before a handle could open.
No unknown response/possibly executed operation is replayed. The request GUI now
uses the cancellable worker path described below; a separate standard-user
desktop/OEM session still requires qualification.

The real-service E2E pipe driver drops privileges and disables its administrator
SID in a restricted token, verifying administrator membership is false before
calling the shared client. This exercises AU-only pipe access without creating an
account or editing OS policy. It is a restricted-token transport test, not a claim
that a separate standard-user desktop/OEM session was qualified.

### Per-application trust, not a new machine root

With all managed routes using the pre-body-trusted native transport, a new
installation stores only the school public PEM pin and no longer imports it into
LocalMachine Root. Installation, ordinary traffic, maintenance and updates must
work against the self-signed fixture while its root-store entry is absent. This
reduces privileged trust changes; no certificate validation is disabled, and
hostname, time, usage and exact pin checks stay mandatory.

Removal retains compatibility with an older install's explicit ImportedRootSha1
record, deleting only that recorded certificate. It does not enumerate/delete
unrelated trust, or rewrite existing installations merely because this code was
merged. CI runs the full service/update chain without a root, then intentionally
adds its own short-lived fixture root + old marker immediately before removal to
exercise legacy cleanup; a second new install again must create no root/marker.
Those compatibility mutations occur only in the disposable runner, not on any
user/teacher/classroom machine.

### Cancellable local request window

The request GUI no longer performs pipe I/O on its message thread. It allows one
operation at a time, disables both submit paths while pending (including repeated
commands), clears the PIN field immediately, and displays results inline rather
than opening late modal dialogs. Cancel/Escape and Close remain responsive.
Workers own only their request/cancel state, never an HWND or UI-state pointer;
window destruction cannot deliver a stale completion into a reopened window.

The production client still checks SYSTEM ownership on the connected handle
before writing. Read, write and acknowledgement use overlapped I/O with a shared
25-second waiting budget and cancellation event. Cancellation requests are
followed by completion draining before OVERLAPPED/buffers are freed; abnormal
kernel completion delays must not be disguised as a guaranteed cancellation
bound. This work runs outside the message thread, and closing this GUI does not
stop the service or revoke an already sent teacher action. Cancel/timeout messages
explicitly describe the possible unknown outcome, with no automatic replay.
See [overlapped pipe I/O](https://learn.microsoft.com/en-us/windows/win32/ipc/synchronous-and-overlapped-input-and-output)
and [CancelIoEx lifetime requirements](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex).

CI tests pending read/write cancellation and deadlines on disposable user-owned
pipes, separately from the public client's mandatory SYSTEM-owner refusal test.
A fixture links the actual window code to a separate deterministic sender, testing
invalid PIN, repeated clicks, Cancel, timeout, close while pending and reopening.
It is not packaged with the product and introduces no production test override.
The actual GUI is also tested with an absent service; authenticated installed
service/PIN exchange remains covered by the existing restricted-token E2E suite.
None of these tests is a claim of physical Win10/OEM desktop qualification.
