# 手机受保护业务切片

实验性 Go 业务包，只供成功完成系统设备认证的原生持钥层调用。已通过原生桥接入 Android 受保护首机初始化、变量 CRUD、上下文恢复、退出与自撤销；每次业务操作要求系统认证。整体 `realVaultReady=false` 仍保留，尚未完整的能力继续拒绝。此包不是生产可用声明。

## 已实现的在线链路

- 注册、验证邮件证明、登录：密码只按既定 SHA256 派生，经验证证书的 HTTPS 发送；固定派生凭据不持久化，也不用作保险库钥。
- 首管理手机初始化：独立 Ed25519/X25519 设备钥、随机环境钥与随机离线恢复种子；设备和恢复 HPKE 封套；恢复签名的根绑定。用户完整重输新恢复码，由重输种子派生恢复签名钥，与设备签名共同完成绑定账号、会话、nonce 和 proposalHash 的一次挑战。先查询未知结果，再用原 proposal/id 重试。
- 读取：已确认本地根固定管理签名公钥，设备持钥 boot 获取短时设备绑定会话；拉取由既有 `PinnedVerifier` 完整验签、检查授权/版本/序号并解密，再保存视图缓存。
- 环境新增、改名、删除：当前 Admin 授权逐次检查；新环境独立钥、设备封套及当前恢复封套；环境名称以独立域 AEAD 加密。签名完整请求先原生保存，接受后只用同一个验签 pull 的精确 id/原序号/内容指纹确认。最后一个环境删除仍按服务端实验性门槛拒绝。
- 变量设置、删除：复用 `syncclient.Writer` 的持久加密请求日志和精确 `mutation-status` 查询；重试保持原 nonce、密文、签名与 id。服务器接受后经相同 pull 下发，不乐观改本地值。
- 原生上下文重启恢复、离线读取已验证缓存。已知全设备撤销使旧会话失效，重新 boot 拒绝后，立即清本地信任、缓存和请求资料，持久化 `AccountClosed`，清该工作流进程中的私钥并关闭对象；关闭上下文不能靠登录自动恢复权限。

首根手机批准使用独立 `ApprovePairing`/`RetryApproval` 的完整 v2 来源和受保护事务。受限恢复及完整新码轮换使用独立 `BeginRecovery`/`BeginRecoveryRotation`/`CompleteRecoveryRotation`，详见 [RECOVERY.md](RECOVERY.md)，当前 Go HTTPS 已验证，Android 恢复操作尚未接入。独立 Go `EnrollDevice/ApprovePairingV3` 与 origin 双签环境新建/轮换已完成真实 HTTPS 切片，见 [MANAGER-ORIGINS.md](MANAGER-ORIGINS.md)；这些新 API 尚未接入 Android。角色管理、账号重置、真实手机后台同步以及丢失全部设备后显式恢复新管理设备的闭环尚未完成。旧 `ApproveDevice`/`Recover` 简化接口仍返回 `ErrUnsupported`；不会把服务器未签名设备目录转换为可信管理公钥。

## 原生持久层合同

`New(Config)` 的私钥和 `ProtectedState` 只能来自系统强认证后原生 AES-GCM 验证解包，不能作为 MethodChannel/Dart 或服务器输入。`SaveProtectedState` 必须原子保存、验证完成后才返回成功；失败阻止新共享写入。Android 适配使用独立可变长、版本化、noBackup 的 AES 文件与独立 AAD，绑定 endpoint、账号/代际、两公钥和 checkpoint；不能塞入当前固定 72 字节钥匙材料文件。必须处理原生保存失败与撤销后的钥匙文件清除，不能只显示错误然后复用旧资料。

内层上下文也严格绑定完整 HTTPS endpoint、设备 ID、独立两公钥、账号/代际、本地根及已见检查点。重复字段、额外字段、无效 UTF-8、跨 endpoint/设备/账号、合成夹具标记、未确认根的云缓存与非法签名请求会拒绝。`AccountClosed` 不通过直接改布尔值复活。

`ExportProtectedState` 只给原生 AES 持久层：包含已验证的明文缓存、标签、授权封套、检查点和签名密文请求日志。待初始化阶段另包含短时随机登录 session，供丢失接受响应后查询；初始化确认持久后清除。上下文不保存私钥、密码、固定登录凭据、恢复种子/码。自撤销待决期间有短时随机会话例外：原签包绑定的随机设备 session token 仅密封保存至原挑战到期，以支持原请求查询与精确重试；到期擦除，不换会话重签。受限恢复另保存仅用于原恢复流程的随机 token，最长至服务器 15 分钟截止，过期擦除；它不等于设备可信或管理授权。严禁返回 Dart、日志或明文文件；`View` 才是可给界面的值视图。软件钥及运行时副本不保证始终硬件内或全部安全擦除。

本机 native API 的调用、加密保存、操作 id 生成和结果序列化须串行。每次系统认证后调用 `New`，操作结束调用 `Close`；取消认证不得调用业务。为 Go 合成测试注入的 `HTTPClient`/`Now` 不属于 Dart 命令格式，TLS 禁止 `InsecureSkipVerify`，拒绝 HTTP/带凭据/查询/fragment endpoint，重定向不传会话。

上下文当前上限 8 MiB，环境请求日志和变量 Writer 日志各至多 32 条；超过时拒绝写入，不抹除旧幂等证据。这是实验性容量门槛，尚无手机日志压缩或迁移流程。服务器另有单账号容量限制；竞争导致 expectedSequence 冲突不会自动产生新 id 或签名。

## API 与验证

原生 Go 持钥层：`New(Config)` → `Register`/`VerifyEmail`/`Login` → `BeginInitialization`（仅此处显示完整新恢复码）→ `CompleteInitialization`（完整重输）→ `Pull`/`View`、`CreateEnvironment`/`RenameEnvironment`/`DeleteEnvironment`、`SetVariable`/`DeleteVariable` → `Logout`（退出且要求原生删除保护资料）/`Close`（只关闭本次已认证对象）。初始化返回 `ErrPending` 时保留原生受保护 proposal，先 `QueryInitialization`；不能偷偷生成新码或新设备。已接受但未完成验签下发返回 `ErrAcceptedNotApplied`，不会伪报完成。

固定工具：仓库 `mise run test-race` 覆盖普通 Go 业务；独立工作区验收由 `mise exec -- go test -race ./acceptance -run TestMobileWorkflow -count=1 -v` 执行。测试只用合成 `.invalid` 邮箱、测试中生成的钥和凭据、捕获发信替身、临时 SQLite、127.0.0.1 HTTPS 代理及 Go AES 原生边界替身，不读取宿主 env/真实钥或发送外部邮件。

2026-10-03 本机证据：Go 手机与环境 wrapper race 通过；真实 Go→HTTPS→TS SQLite 首机初始化/环境与变量 CRUD/已接受响应丢失后的原 id 查询恢复/加密上下文重启/保存失败先拒上传/离线视图/全局撤销清空关闭，普通测试通过。最终 HTTPS race 也通过（端到端单项 1.05 秒，完整执行 2.534 秒）；Go AES 替身不算 Android Keystore 高层业务接入或强生物实际验收。

## 自撤销切片证据

`RevokeSelf(ctx, id)` 要求当前全部环境 Admin，真实服务端原子撤销自身设备、会话和授权。原签包和短时原 session 必须先经原生密封保存，再提交；待决期间普通缓存/CRUD 关闭，`SelfRevocationInfo` 仅返回 id、状态和到期时间，仍可退出。仅已知 200 完成回执报告 completed；已接受响应丢失后原 status 401、重新 boot 403，只报告授权失效及原请求结果未知，并清本机资料。到期原 bearer 擦除、禁止再 POST，不隐式创建新操作。细节见 [SELF-REVOCATION.md](SELF-REVOCATION.md)。

本机 Go `go test -race ./mobileworkflow ./syncclient -count=1` 通过（2.206 秒 / 3.752 秒）。工作区真实 `go test -race ./acceptance -run 'TestMobile(SelfRevocation|Workflow)' -count=1 -v` 通过：原手机纵链 1 项与自撤销 5 子项，包执行 6.240 秒。Android 原生代理记录最终高层 suite 12/12 通过，184.013 秒，覆盖已知完成、丢失接受响应、密封上下文重建、待决缓存关闭和 alias/key/state 删除；此证据与 Go AES 替身分开记录。

## 受限恢复切片

独立 `RecoveryInfo`/`RecoveryView` 使用完整恢复码验证根并恢复已签历史数据；`BeginRecoveryRotation` 显示独立新完整码，`CompleteRecoveryRotation` 要求完整重输、原 ID 查询、原 nonce 签名、原子全封套替换与同 vault 验签/HPKE/AEAD确认，最后原生保存成功才确认。所有状态 `trustedDevice=false`。新环境/跨版本/非根来源缺 origin 时拒绝，不能据此宣称全设备丢失后的管理恢复已完成。Go 真实 race 3 主项/10 子项通过，10.850 秒；原生恢复操作未跑。完整合同、密封字段及限制见 [RECOVERY.md](RECOVERY.md)。
