# 当前用户与后台服务的本地通信

后台服务持有唯一 `localstate.Engine` 与 Store 锁；CLI 不直接读写这个状态文件。`localipc` 只提供本机已授权用户的激活、优先级、停用、override 设置/删除、暂停/恢复、退出账号、状态和明确导出。它不能导入云快照、修改签授权、注入设备钥匙或建立账号信任。受保护后台可另外注入 `OnlineWrite` 回调，接受显式 put/delete/import/write-retry；fixture 状态禁止共享写。

## 协议与生命周期

`Listen(Config)` 接收后台 Engine、provider、固定本地身份以及退出回调。`Serve(ctx)` 的生命周期由系统服务控制；一次 CLI 断开不会取消后台。`Call(ctx, Endpoint, Request)` 每次连接发送一个命令。CLI 和后台定时器 `Server.Reconcile` 使用相同串行操作锁，状态更新持久化后再回复。

协议是四字节大端长度加单个 UTF-8 JSON 对象，版本为 `1`。请求上限 512 KiB、响应上限 8 MiB，拒绝未知字段、额外 JSON、无效环境/变量名、内部保留前缀和越界载荷。默认最多同时连接 16 个、每个请求 5 秒截止。错误只有固定码，不回显 provider 错误或变量值；`status` 只有元数据，`export` 是用户明确请求的明文输出。本包不记录请求、token 或值。

断连时命令可能已经持久化；调用方查询状态再重试同一操作。激活、同值 override、暂停等本机操作可重复收敛。优先级命令只改变已激活环境，不能偷偷激活。共享写回调只转交在线加密签名封装，不提供离线共享写入旁路。变量值由stdin进入，导入仅含已选中的 map；帧拒绝其它命令携带请求ID或选中值。共享调用最长一分钟，断连可能已有接受；用原请求ID查询/重试，错误与响应只含固定码和接受序号等元数据。

退出账号先由 Engine 持久化 session epoch 并清云缓存，使旧 `syncclient` 及迟到 pull 无法回写。`OnLogout` 由可信后台控制器负责停止、等待旧同步并删除设备/session/trust/writes 固定 slot；本包不持有 Vault。provider 恢复失败时仍保留清理后的缓存、原值和待恢复名字，重启继续逐项恢复，不能整文件覆盖其它修改。停止后台和正常崩溃保持配置，不执行退出账号。退出状态有持久 AccountClosed 墓碑；即使崩溃在清slot之前，重启也先完成材料清理，只有新的已确认完整入网才能解除。

## 截止时间、传输分类与诊断

普通请求的截止时间从服务端开始处理连接算起，包含读帧、等待串行 owner、持久化和回复；共享写在完整请求读取后沿用已有一分钟预算。`Timeout` 与连接容量没有因并发测试调整。串行 gate 的排队等待响应服务端请求上下文的截止或取消，取得 gate 后也检查上下文；已经过期的排队请求不会开始修改 Engine、调用共享写或 provider。后台 `Reconcile` 使用相同 gate。请求已经开始后，Store 的同步 Save/fsync 无法强制中止，断连或超过预算仍可能已持久化，不能把没有回复当作未执行；也不会为了赶时限省略原值记录或其它持久化。CLI 提前取消/关闭连接不会撤回已发送的完整请求，服务端没有将连接关闭当作账号退出；此时也须查询状态或原请求ID收据。

`Call` 将连接失败、截止、断开或截断归入 `errors.Is(err, ErrUnavailable)`，可声明 `var transport *TransportError` 并用 `errors.As(err, &transport)` 获取固定 `Phase` 和 `Failure`。只有完整帧中的错误长度、JSON、字段或版本才是 `ErrProtocol`。服务端先到期关闭连接时，客户端只能知道 `disconnected`，不能假定它获知服务端的 `timeout`；自己的截止会得到 `timeout`。这些错误不会包装系统原始错误或路径。收到完整回复且 `OK=false` 时仍保留固定业务错误码，包括 provider/持久化失败；取消不会将它变成成功。

`Config.Observe` 默认关闭。显式启用时只回调固定阶段/失败枚举、排队/执行/总耗时、预算及是否开始执行/业务成功，不包含命令、账号、路径、变量、值或原始错误。`queue` 事件表示完整合法帧即将等 gate，其它事件表示连接结束或容量拒绝。回调须快速返回并自行同步；它与对应 worker 一起完成，不另起日志或排队服务。

受控回归仍使用真实 FileStore Save/fsync、`Timeout=1s`、`MaxConnections=32`，人为阻塞第一个 Save 约 1.1 秒。修复前第二请求排队 1119ms 后仍执行 override，五次 Save 完成后写响应头超时，客户端错误被误归 `ErrProtocol`。修复后第二请求约 1001ms 即离开队列，在第一个 Save 尚未释放时客户端返回传输中断，override 未执行；已经开始的 status 继续完成两次 Save，回复超时也准确记录。容量关闭的原生竞态还实测出现 `ENOTCONN`（60 次受控关闭中 2 次），现与 `EPIPE`、`ECONNRESET`、EOF 同属固定断开类别，另有确定性 errno 回归。另有真实 socket 的正常回复、完整畸形回复、头/体截断和容量拒绝分类回归，以及取消与持久化失败并存的回归。

原来的 20 并发、容量 32、预算 1 秒测试保留全部成功断言，并输出无秘密的最大排队/执行/总耗时。定向 race 重复三次通过，最大排队 278–286ms、执行 21–22ms、总耗时 292–300ms，唯一断开记录来自测试显式关闭的空连接，超时与其它失败为零。此前完整 race 的三次失败没有采集到阶段诊断，不能把受控复现当作它们的确定历史原因。主机负载或磁盘延迟确实超过预算时，原测试仍应失败；本实现不承诺在任意负载下一秒内完成所有请求，也不通过增加预算、容量或忽略失败掩盖这一点。

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
