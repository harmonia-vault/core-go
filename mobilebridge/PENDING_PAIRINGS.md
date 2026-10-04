# 前台待配对请求提示桥

这是实验性只读底座，尚未接入手机 SDK、MethodChannel 或 UI，能力默认关闭。采用 MIT 许可证。

## 调用合同

Go 原生句柄独立提供 `ValidatePendingPairingsCommand` 和 `ExecutePendingPairings`，没有加入普通 `Execute` 或 `WorkflowProfile.operations`。每次系统认证所得句柄只执行有界操作，关闭该句柄不会创建后台轮询。参数是严格 JSON：

```json
{"version":1,"endpoint":"https://synthetic.example.invalid","operation":"pendingPairingRequestsV3"}
```

只有 `pendingPairingRequestsV3`、`pendingPairingRequestsV4` 两种操作。不接受账号、设备、公钥、token、短码或请求方声明的权限。endpoint 必须精确等于原生保护状态。V3 使用已验证的 origin 来源，V4 使用连续恢复来源；没有相应来源的 legacy/P4 设备明确拒绝，不降级。

成功是 `{version:1,operation,ok:true,data}`，data 严格包含：

```json
{"accountId":"synthetic-account","accountGeneration":"1","approverDeviceId":"synthetic-manager","certificateVersion":"3","capabilities":["issuer-origin-v1"],"requests":[{"idempotencyKey":"synthetic-request","initiatorDeviceId":"synthetic-new-device","state":"pending","expiresAt":"2030000060"}],"authoritativeForApproval":false}
```

V4 的 certificateVersion 是 `4`，唯一 capability 是 `issuer-recovery-v1`。请求 state 只允许 `pending` 或 `approved`。所有 expiresAt 都是规范十进制秒字符串。失败返回空输出与 Go error；原生调用层必须使用既有固定错误分类，不能把失败变成空的成功列表，也不能输出错误中的 HTTP body 或凭据。

## 权限与边界

每次显式前台刷新都先检查当前保护状态，执行成熟设备持钥 Boot、完整来源验证 Pull 和原生持久化，再请求固定 GET `/v1/accounts/{accountId}/pairing-requests-v3` 或 `v4`，没有 query。设备会话与账号代际使用既有认证头；服务器每次重查当前设备、会话及至少一个有效 Admin。客户端也在请求前后重查 epoch、账号代际、暂停状态和本机已验 Admin。登录会话不能替代设备信任，离线 Admin 不能独自返回提示。

两个 GET 的实际响应读取上限为 32 KiB，其它成熟路由仍是原来的 8 MiB。JSON 禁重复或未知字段，必填字段不能为 null。最多 64 条，原请求 ID 不得重复；错误账号代际、版本、capability、名称或期限格式都硬拒绝。合法但已到期的提示在返回前滤除，剩余期限不超过服务器 120 秒加 5 秒容差。

提示只携带真实请求 ID、设备 ID、状态和到期。没有服务器序号、设备名、平台或环境明文。`authoritativeForApproval:false` 明确表示它不是可信设备身份或可批准权限；真正批准仍须成熟 PAKE 双向确认、完整来源验证及明确角色/期限。提示列表不形成新的持久安全状态。

句柄排空锁保持原有合同；网络有 30 秒上限，不持有跨账号全局 registry 或原生持久锁。锁外 Invalidate 可以及时取消网络，迟到响应经当前保护状态和 epoch 再检而拒绝。全局撤销或代际失效沿成熟清理语义传播，不能吞掉 `ErrTrustInvalidated`。

## 本片验证

客户端两个定向 race 测试通过，覆盖 V4 已验来源、真实 32 KiB 读取边界、代际/版本/capability、重复 ID、到期过滤、HTTP 拒绝、只读和暂停的零 GET。原生两个定向 race 测试通过，覆盖严格 command、绑定投影、输入独立复制、普通入口仍关闭及未受信零网络/零持久化。三个受影响 Go 包 vet 通过。

一个真实回环 HTTPS/TypeScript/SQLite 场景通过：成熟原生 BoringSSL PAKE 将管理设备 B 入网；C 提交真实待批准请求；B 每次新原生句柄 Boot/Pull/GET 取得精确提示；锁外 Invalidate 取消且迟到提示不输出；原管理设备签名降权为只读后 B 不再请求列表。AES Save/Check/CAS 是 Go native 测试适配器，旧 cert3 状态保持成熟 Save 路径，不能据此声称手机系统认证或 SDK CAS 已验。

首次类型编译失败、联合测试错误使用 DAG-only adapter 和管理原批准未完成的失败证据均保留；修正只涉及本片类型或合成测试续办，不放宽业务门槛。未运行手机 SDK、模拟器、UI、真实用户账号或宿主环境变量测试。
