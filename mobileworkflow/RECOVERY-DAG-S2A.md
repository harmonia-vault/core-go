# 手机恢复 DAG：S2a 原事务冷查询

本片只增加 Go 高层 `Workflow.QueryRecoveryDAGOriginal(ctx, completeCurrentCode)` 和独立的 GET status 严格解码。没有接 native ABI、Flutter、平台 provider 或能力开关。实验性安全软件，不能据此宣称完整恢复或生产可用。

## 原包与单次会话

调用必须已有 S1 保护的原包和原 pin，且提供完整当前恢复码。账户、代际、原 ID、原签名包与 pin 全从已保护状态取出；不接受调用方替换。仅 `SaveSealed` 的旧 provider、已关闭账户、过期 owner、损坏状态或没有原包在网络前失败。每次创建新的受限 RAM 会话，30 秒上限；同一 Workflow 的重入返回 Busy。关闭或退出登录取消在途 context，callback port 在调用结束时排空并脱离，session 在自身锁外关闭。没有长期 registry。

GET status 的 `accepted` 必须显式为 JSON bool。false 只允许 `operationId` 与 `accepted`；true 必须有精确五字段、合法正整数 sequence 和对应种类 hash。随后仍核对原 ID、原 hash、预期 sequence 与已接受下界；缺失、null、错误类型、额外字段等不能变成“未接受”。POST receipt 沿用原合同。

| observation / confirmation | 含义 |
| --- | --- |
| `accepted` / `receipt-observed` + error | 已观察原回执，但 resolve 或持久 CAS 未完成；不可作为持久成功或设备信任 |
| `accepted` / `original-verified-and-saved` | 真实 resolve 验证原包并完成 S1 保存，最终重读原包、typed metadata 与 owner 检查通过 |
| `not-accepted-at-query` / `none` | 本次真实 status 明确 false；原包仍 pending，不能推定已终止或可换新 ID |
| `unknown` / `none` + error | 当前码不正确、网络/响应异常、过期 owner 或最终状态门槛失败；不能替换为负观察 |

`Pending` 是 S1 持久元数据，与本次 observation 分开。任何结果均 `trustedDevice:false`、`rotationRequired:true`。新会话不会因旧回执而清掉自己的轮换要求。accepted 路径在 resolve 后再次检查这些状态；失败不能返回可用成功。仅查询阶段不申请业务 nonce、不重新签名、不提交 transition/recovered 原包、不创建新原 ID。

完整码只用于当次认证，不保存 bearer。传入 byte slice 返回时清零；既有字符串 API 的不可变 string 和 GC 副本不能保证物理擦除。合成测试中的包注入仅位于测试文件，不构成产品 API。

## 精确验证

固定基线：core `08dcf018bc0f1969b799703dcf74b08d3caa69aa`、workspace `cefe6d7e21939c941b997c11a39d528795a86605`、server `6c39ed101faac7cd9196eb1b7476970bb03d0a00`、protocol `ccf8ec67a1bda84589d90c007b4b70c93042151c`。使用 Go 1.26.4 / Node 24.16.0 / tsx 4.20.6，darwin/arm64 默认 Go build，无 BoringSSL tag。

- core `mise run test-mobile-dag-query`：受影响四包 race **425 PASS 事件、0 FAIL**，含新增组件 34 个 PASS 事件；覆盖既有 cert4、业务保存、registry 与 S1 回归。主测试与 subtest 各算一事件，不表示 425 个独立端到端场景。
- workspace `mise run test-mobile-dag-query-https`：**三个真实原事务场景、4 PASS 事件、0 FAIL**，10.558 秒。固定 Go→经验证的隔离 loopback TLS→TypeScript→临时 SQLite，合成账号。native 持久层为测试 AES/同槽 CAS callback。
- 同四包 `go vet` 成功；core 全消费者编译成功，13 个测试包与 5 个无测试文件包，**0 个测试实际执行**。

三个 HTTPS 场景分别验证：真实 transition 接受但响应丢失后关闭旧 RAM 会话，当前完整码重开并在保存故障/重开后确认原包；未提交原包的负观察与断网/坏响应后原 ID 保留；独立 Workflow 在 status 屏障期间退出登录，旧查询不得覆盖 AccountClosed/新 epoch tombstone。另含错误旧码与 resolve 后伪造 `rotationRequired:false` 的定向负例。九次 query 与 preparation 分开计数；query 的业务 challenge、transition/recovered POST 为零，认证 challenge/session 各九次。计数来源是测试 transport，不是服务端审计；先前账户初始化不在 preparation 计数区间。

源码、产物 hash 和分阶段计数见 [脱敏结果](evidence/recovery-dag-s2a-result.json)。早期 29 组件 PASS 与两个 HTTPS 原事务中间运行日志保留，不追认为最终源码；本片以最终重跑为准。

## 尚未覆盖

服务端仍没有旧未接受事务的权威终止接口。本片保留 pending，不能凭本机时钟写 expired/abandoned，也不能标 Applied。真实 HTTPS 高层场景只覆盖 transition-v2；recovered-v2 的 exact wire 分支有组件测试，真实高层查询未跑。未做 S2b、新事务提交、完整码重输交互、显式环境/角色/期限登记、Boot/Pull 后可信、P4 高层或完整恢复链。

真实平台还必须让普通 SaveSealed、DAG CAS、Logout、Forget/delete 的所有 writer 在同槽 OS/owner 锁下比较认证时捕获的完整旧密文、SessionEpoch 和平台 lifecycle epoch，拒绝旧 owner 的迟到写；不能 callback 内重新读取后普通写来假装 CAS。S2a 仅合成原子 provider 验证，未完成 SDK 接线。gomobile 的静态 `SealedStateStore` proxy 不保证暴露 `AtomicSealedStateStore`；后续需明确 typed opener 与实际 JNI/ObjC Check/CAS 回调证据。未证明手机认证、硬件安全、PIN 平台或真实进程 kill 后磁盘恢复。

本片未改 server、protocol、S1 schema、平台 ABI、UI 或 cap。合并 mise task 时须加法保留其他 owner 已发布的新任务。原始日志、合成密钥/CA、临时数据库与私有路径不进入公开文件。
