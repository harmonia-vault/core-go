# 手机账号重置 P3 业务接线合同

这是独立候选，基于 core-go `78d7dd845307abb9566cf8a6d0711c4977841c11`、server `36ab16fbaadacd766548e201c05acd5e80ccb89b`、mobile `09d3ce4239fe514cf1bebd4c3efb6e743a2013b6`。仅新增 `accountreset` 包，不改后端协议、DAG、Workflow、native plugin 或 Flutter，不开放产品能力。它完成已有重置协议的 Go 调用与同一进程内的原请求续办，不代表 P3 产品项完成。

## 已有后端与缺口

`server/src/http-account.ts:accountRoute` 已提供三个 POST；`server/src/account-lifecycle.ts:AccountLifecycle` 的对应实现如下。所有证明只进 JSON 请求体，不能放 URL、日志、监控、剪贴板持久存储或普通设置。

| 动作 | 请求 | 确认后的响应 |
| --- | --- | --- |
| `requestProof(email,"reset")` | `/v1/account-reset/request`，`{email}` | `{accepted:true}`；不证明邮箱存在或邮件已到达 |
| `resetStatus(accountId, proof)` | `/v1/accounts/{id}/account-reset/status`，`{accountGeneration,challengeId,token}` | `{state:"pending"|"complete",accountId,accountGeneration}` |
| `reset(accountId, input)` | `/v1/accounts/{id}/account-reset/complete`，原 proof 三字段加 `newCredential`、`confirmation:"DELETE_OLD_VAULT"` | `{accountId,accountGeneration,replayed}` |

邮件中的完整证明是 `{accountId,accountGeneration,challengeId,token}`。token 为规范无 padding base64url 的随机 32 字节，服务器仅保存其哈希；绑定用途、账号代际、当前密码验证值与十五分钟期限。重置不要求旧可信设备、旧密码或恢复码，但要求有效 reset 邮件证明及明确破坏确认。verification 证明不能替代 reset 证明。

后端在事务外计算新 Argon2id，再在唯一账号权威事务内重核旧代际/密码验证值/证明/期限。账号 ID 保持不变，generation 加一，旧 vault、设备、公钥、授权、会话、事件、恢复钥/封套和其他旧扩展字段全部删除。`emptyAccount` 生成新空账号，保留已完成注册 admission 与验证策略；独立 `registrationAuthority.firstCompleted` 不被 reset 修改，因此永久首号策略不重开。

后端已有 `account-lifecycle.test.ts`、`worker-account.test.ts`、`registration-policy.test.ts`、`registration-worker.test.ts` 对这些行为的用例。本候选只读这些源码，未复跑后端、SMTP、Email Service 或 workerd。当前 `mobileworkflow` 只有 Register/VerifyEmail/Login 等接口，`mobilebridge/workflow.go` 命令集和 Flutter `NativeWorkflowAdapter` 没有 reset 入口。

## 新 Go 接口

`New(Config{Endpoint, HTTPClient})` 固定 HTTPS 地址、禁止重定向和 cookie jar，拒绝不可检查的 transport、关闭证书校验或弱 TLS。HTTPClient 只由可信 Go/native 配置提供，不接收 Dart 提供的 CA 或 TLS 参数。

- `ParseProof(data)`：完整 proof 四字段，严格拒绝重复、别名大小写、额外字段、null、非字符串、非规范 token/generation。
- `Client.RequestProof(ctx,email)`：只发邮件请求；不返回账号目录信息。
- `Client.Query(ctx,proof)`：允许没有旧设备的新手机凭原邮件证明查询；pending 不自动提交，complete 不发行任何设备信任。
- `Client.NewAttempt(proof,passwordBytes,confirmation)`：确认必须为完整固定字面值；消耗并清理传入密码缓冲，只做原始 SHA256，生成一次私有固定 JSON。没有改密码、改 proof、改 endpoint 的后续接口。
- `Attempt.Submit(ctx)`：首次明确提交，或原查询 pending 后显式重试；结果不明保存 `unknown`，再 Submit 立即返回 `ErrQueryRequired`，不发请求。
- `Attempt.Query(ctx)`：只查固定原 proof；pending 不提交。确认 complete 后清理可控的私有 payload，并保存只含公开元数据的结果。
- `Attempt.Close()`：取消请求、清理持有的可控缓冲；并发和晚到结果不交付给退役调用者。不宣称 Go/平台所有不可变字符串副本可物理清零。

响应严格校验账号 ID 与原值相同；pending generation 必须等于原值，complete 必须恰为原值加一。旧 generation 为 uint64 上限即拒绝，不能溢出或接受跳代。提交后的传输、HTTP 或解码错误都保守记为结果未知，先查询原证明；仅服务端经过既有固定白名单过滤的错误码可以显示。

Go 输出 `Outcome` 的字段为 `state`、`accountId`、`accountGeneration`、`source`，仅 commit 回执有布尔 `replayed`。`source` 是 `local`、`status` 或 `commit`，避免把 status complete 伪称某个新密码已被接受。输出不包含 proof/token/password/credential、deviceId、trustedDevice 或旧 vault。结果表示这一重置已由服务器确认，不等于已登录、设备可信或新 vault 已初始化。

## Flutter 与 native 的最小接线

Flutter 业务入口展示明确选定的 HTTPS 服务与邮箱，发起证明请求后由用户粘贴完整证明。native/Go 校验 proof，UI 展示目标账号及“永久删除旧 vault、所有设备授权和恢复状态；旧数据不会恢复”的含义，并要求显式破坏确认与新密码。密码不能被复用为 vault 钥。

本机破坏清理前，先用同一 proof 向已固定服务执行 Query，取得通过严格账号/代际校验的 pending 或 complete。只有粘贴 JSON 通过格式检查不够；无效/过期/用途不符/查询未知均不允许清理现有本机账号。原生还须将 proof 的账号与旧代际匹配已认证的本机 account/slot，拒绝借另一账号的有效 proof 清理当前槽。

如果当前手机存在对应旧保护槽，native 必须复用已实现的真实 Logout 流：退役旧后台/前台 owner，经真实平台保护和 Go 本机退出，完成原设备材料与受保护业务状态的精确清理。只有原生真实完成证据才能允许 destructive Submit；不能接收 Dart 的 `cleanupComplete`、空列表或其他布尔作为证明。范围必须绑定原服务、账号和槽身份，不能清理另一账号。失败/未知保留阻塞，不开始云端删除。用户确认文案应说明本机先退出，断网不等于云端未重置。Query 已为 complete 时仅收敛对应旧本机槽并返回未可信账号流程，不再提交。

新手机没有旧 trusted device 时仍可使用邮件证明。是否存在旧材料及其安全缺失必须由现有原生槽检查确认；不能要求“旧设备可信”来授权邮件重置，也不能用新造空状态冒充既有槽的清理完成。

native 持有 `Attempt`，每次只允许一个当前操作，绑定 endpoint、账号、challenge 与本次前台生命周期/操作 epoch。MethodChannel 只承载明确操作、proof/密码的短暂输入和公开 Outcome，不能开放任意 URL/HTTP/body。密码与 proof 的可控字节缓冲用完清理；不暴露 Go owner、完整受保护状态或任意文件读写。后台、取消、切换服务/账号和退出均调用 Close 并阻止晚到结果重新导航或恢复旧缓存。SDK/存储/前台具体 hook 仍由根集成，本包没有伪造这些证明。

UI 状态为：请求证明、等待输入、待破坏确认、提交中、结果未知、原事务 pending、已完成。未知只提供原事务查询和退出；查询 pending 后允许用户明确“重试原请求”，不会重新输入密码或创建替代内容。查询 complete 后回到未可信账号流程，正常登录新账号并重新初始化新 vault；不沿旧 checkpoint/root 恢复旧数据。无通用管理界面跳转、自动设备授权或自动 vault 初始化。

本候选的 Attempt 仅在 RAM 保存。进程死亡后若没有原生密封的原 payload，只能重新输入原邮件 proof 做 Query；不能把新密码/新构造 Attempt 冒充原请求重试。需要冷启动继续 Submit 时，必须由 native 受保护、绑定同一 endpoint/proof 的原请求记录恢复，不能写普通 Dart 设置，也不能借 P1 DAG journal 存重置状态。本切片不实现或声称该持久化。

## 本次验证范围

仅对新包运行必要的纯内存 HTTP transport 业务测试：严格 proof/TLS 配置、精确请求与 SHA256、结果未知先查原事务、冻结 payload 原字节重试、complete/status 账号及 generation/字段类型、取消与晚到结果。测试不监听端口，不发送邮件，不运行服务或 VM，不使用真实凭据，也不构成真实 HTTPS/native/Flutter 产品通过。执行结果和源码摘要另在候选根目录冻结。

实际 P3 完成条件仍沿 workspace 固定清单：同一产品快照从实际手机界面通过合成邮件证明与破坏确认完成一次重置，验证旧代际设备/会话失效、旧 vault 不恢复、永久首号策略不重开，并核对本机真实清理。此处不新增独立测试路线图；UI 及 native 接线未完成前不开放能力。
