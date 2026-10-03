# Go 手机冷恢复来源投影候选

此独立切片基于公开 core-go `1544501fe6b1637d3cbe49d347c39a56ee344fe1`，仅新增本目录的 `source_projection.go`、`source_projection_test.go` 和本说明。现有 `View`、`Pull`、mobilebridge 五字段 restoreSession ABI、profile、Plugin、Dart 和 AAR 均未改；两个新方法未对 Android 发布或开启 capability。

## 同一锁内的新 API

`Workflow.RestoreSessionWithSource()` 离线重新验证来源与缓存；`Workflow.PullWithSource(ctx)` 先沿现有线上 refresh/验签流同步。两者在同一 Workflow 锁内建立 `TrustedSourceView`：

- 外层固定 version=1、trustedDevice=true、accountId/accountGeneration/deviceId、view 与 approvalSource。
- approvalSource 仅包含已验来源 profile、certificateVersion 字符串3或4、与 view 精确相同的 checkpoint，以及排序的 adminEnvironmentIds；不导出根、公钥、证书、authority、token 或签包。
- 首机必须精确 InitialAuthorities 验签；V3 必须 Applied、接受序号、完整双签收据与绑定；V4 必须 Applied 接受的完整恢复登记包及恢复来源。
- 复用 originVerifier、ValidateStoredIssuerEvidence、CurrentIssuerEvidence / CurrentIssuerRecoveryEvidence。Admin 候选通过现有 PrepareEnrollmentProofV3/V4 按当前本机角色、代际、数据版本与期限检查。结构只选择必须验证的分支，签名或账本错误不切 parser、不 fallback。
- 期限由本地引擎清缓存，再重验确切新状态；RO或已到期无 Admin 选择。暂停时清单为空。身份登录、公有地址和 runtime 广告不进入此信任路径。
- 原签名业务事务未知或接受未应用时，ErrSourceProjectionPending 返回零 DTO，保留原 journal 与 ID；受限、待完成、缺来源和未知来源账本也拒绝。原 PendingBusinessOperations/RetryBusinessOperationByID 仍可办理原事务。
- 最后原生 SaveProtectedState 全部成功后才返回结果；包括在线 refresh 已保存而最终来源保存失败，也返回零 DTO。Close 不得穿越同一把锁。

离线来源不承诺服务端当前未撤销，不批准新设备。实际批准仍须在线刷新、明确 PairID/短码与环境/role/expiry，并逐次系统认证。公共地址持久化尚未在此切片实现。当前 Flutter 冷恢复审批版本0保持关闭；后续桥接必须固定独立意图/DTO与实际 Android 证据后再开启。

## 真实验证

新增8个Go测试函数，覆盖19个叶场景；使用成熟 Ed25519、HPKE、完整来源验证和真实本机 HTTPS 合成服务。V3沿公开确定向量重新签本机上下文，恢复V4经完整恢复钥签名和HPKE证明后重新建立接受来源，不以静态 DTO 或信任 bool 代替验证。

定向 race：`go test -race ./mobileworkflow -run '^TestSourceProjection' -count=1 -v` **通过，6.997秒**。包含三种来源正例；RO和到期清缓存；坏初始授权/V3双签/V4恢复签名、错代、缺源、未知账本、受限和未应用；最后保存失败；真实在线拉取；真实未知签名事务跨重启保持原ID；最后Save与Close的锁隔离。

包级 race：`go test -race ./mobileworkflow ./mobilebridge -count=1 -json` **通过，133个测试/子测试成功、0失败、0跳过**；wall15.906秒，包耗时 mobileworkflow14.635秒、mobilebridge12.027秒。实际 JSON 原始记录和计数保存在候选外层 `go-package-race.jsonl`、`validation-results.json`。

首次定向验证中，三个来源和安全负例已通过，在线测试误用旧 fixture 的撤销计数器断言有一次失败；更正为真实 HTTP `/pull` 路径计数后通过。没有因此改变生产来源校验。

本次未跑 BoringSSL标签、Android、AAR、Flutter或产品用户点击链，不声明整个应用或新原生 ABI 已通过。测试没有读取用户账号、密码、环境变量、旧私钥或会话。
