# 当前用户与后台服务的本地通信

后台服务持有唯一 `localstate.Engine` 与 Store 锁；CLI 不直接读写这个状态文件。`localipc` 只提供本机已授权用户的激活、优先级、停用、override 设置/删除、暂停/恢复、退出账号、状态和明确导出。它不能导入云快照、修改签授权、注入设备钥匙或建立账号信任。

## 协议与生命周期

`Listen(Config)` 接收后台 Engine、provider、固定本地身份以及退出回调。`Serve(ctx)` 的生命周期由系统服务控制；一次 CLI 断开不会取消后台。`Call(ctx, Endpoint, Request)` 每次连接发送一个命令。CLI 和后台定时器 `Server.Reconcile` 使用相同串行操作锁，状态更新持久化后再回复。

协议是四字节大端长度加单个 UTF-8 JSON 对象，版本为 `1`。请求上限 512 KiB、响应上限 8 MiB，拒绝未知字段、额外 JSON、无效环境/变量名、内部保留前缀和越界载荷。默认最多同时连接 16 个、每个请求 5 秒截止。错误只有固定码，不回显 provider 错误或变量值；`status` 只有元数据，`export` 是用户明确请求的明文输出。本包不记录请求、token 或值。

断连时命令可能已经持久化；调用方查询状态再重试同一操作。激活、同值 override、暂停等本机操作可重复收敛。优先级命令只改变已激活环境，不能偷偷激活。IPC 不提供共享云写入或离线共享写入旁路。

退出账号先由 Engine 持久化 session epoch 并清云缓存，使旧 `syncclient` 及迟到 pull 无法回写。`OnLogout` 由可信后台控制器负责停止、等待旧同步并删除设备/session 固定 slot；本包不持有 Vault。provider 恢复失败时仍保留清理后的缓存、原值和待恢复名字，重启继续逐项恢复，不能整文件覆盖其它修改。停止后台和正常崩溃保持配置，不执行退出账号。

## 系统身份

macOS / Linux 使用 Unix domain socket。目标 UID 必须与当前非 root 服务用户一致；私有目录为 `0700`、socket 和所有权文件为 `0600`。服务与 CLI 双向核对原生 peer UID：macOS `LOCAL_PEERCRED`，Linux `SO_PEERCRED`，由 `golang.org/x/sys/unix` 调用。独占 `flock` 防第二个服务占用同一 endpoint；只清理具有本工具所有权标记、同 UID 的旧 socket，不覆盖现有普通文件。路径须绝对、规范解析后不变；所有父目录也拒绝符号链接，只创建最后一级目录，socket 路径长度不超过 100 字节。

Windows 候选使用 [Microsoft go-winio](https://github.com/microsoft/go-winio) `v0.6.2` named pipe。地址从明确目标 SID、服务 SID 和目录派生，用户不能提供任意网络 pipe。保护 DACL 给目标用户最少数据读写权限，给服务 SID 全权；目标用户没有建立同名 pipe 实例的权限。服务与 CLI 分别查询连接对端进程的 token SID；客户端须为目标用户，后台须为指定服务 SID（包括启用的服务组 SID）。使用 Identification 级别，不能通过此接口获得用户 impersonation token。该库的创建实现拒绝远程客户端并要求首个 pipe 实例，[对应源码](https://github.com/microsoft/go-winio/blob/v0.6.2/pipe.go)。管理员或已控制同一用户/服务的进程不在此隔离边界之外。

## 已验证与待验收

- macOS 普通用户：真实 Unix socket、20 个并发 CLI、部分包断连、双向 peer UID 查询、不同配置 UID 拒绝、第二 owner 拒绝、服务重启、暂停撤销、逐项恢复、现有文件/叶目录链接/宽权限拒绝均通过 race 测试。
- CLI 与长期 fixture daemon：后台持状态锁时其它 CLI 可激活、override、导出、暂停、退出账号；退出后后台仍可应答，通过真实 CLI 集成测试。
- 加密 Store 联动：合成账号、随机设备钥匙、临时目录；磁盘文件不含合成明文值或 session，退出账号恢复失败仍删除设备/session 并清缓存，重启恢复原值和删除新增项，通过 race 测试。
- Windows amd64：实现及测试源码交叉编译通过。真实 named pipe DACL、跨用户拒绝、SCM 停止、句柄/token 查询权限尚未在 Windows VM 跑通，不能把编译当原生验收。
- Linux 实际 systemd / SSH 验收由隔离 VM 测试账号执行，结果记录在 workspace 与平台文档；这里不声称已完成三平台开机验收。

macOS/Linux 实验性正式 daemon 已接受保护双签入网收据、设备开机持钥挑战与同步，只有 accepted 且证书验证通过才联网；暂停使用独立授权检查点，退出等待旧 worker。该编排已有合成 TLS 回归。手机接线与三平台原生启动仍需验收，不能把本包与机器保护的通过宣传为生产凭据系统已完成。
