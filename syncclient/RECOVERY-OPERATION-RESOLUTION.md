# 恢复原操作的受限终态查询

这是实验性 Go 业务接口，未接 UI、native ABI 或手机 SDK。首片只支持原保护 journal 中 `sealed transition-v2` 且 `authorizationKind=old-recovery`。`recovered-v2`、管理设备发起的 transition 和 intent/challenged 一律明确拒绝，低层窄会话也在网络前拒绝这些类型。通用 `cryptox` 编码支持公开协议向量，不等于业务入口已经开放其它类型。

`RecoveryOperationTargetFromSealedTransition` 从成熟严格解码/签名验证过的原 journal 还原目标，保留原账号代际、原 ID、设备双钥、恢复 basis、完整环境清单摘要、原挑战摘要和原签包 hash。`DeclaredIntentHash` 是规范化原保护操作的公开摘要，并不声称服务端曾保存客户端的 prepared 清单。服务端的未知目标判断沿已公开协议规则，不把声明变为历史见证。

`OpenRecoveryOperationResolutionSession` 要求 HTTPS、显式 major 2，以及 `recovery-dag-v1` 和 `recovery-operation-closure-v1`。它与普通 `OpenDAGRecoverySession` 共用成熟的一次 nonce/用途/account/generation 精确验证与恢复签名证明 helper。区别在于窄会话仅取得当前受限证明，不下载或解密 vault，也不导出 bearer、钥匙或通用 HTTP 方法。输入码 buffer 尽力清零；`Close` 清理进程材料。

`Resolve(ctx,target,mode,deviceKey)` 仅允许 `query` 或明确的 `resolve-or-close`，用当前 RAM 会话 hash 和目标 hash 签固定域数组。旧 session hash 只是原目标标识。请求使用 Authorization header，不把 token 放 query；响应严格限制大小、major、字段集合、账号/代际/ID/目标 hash 和三态。任何网络或解析错误都不是未接受/已关闭证明。

- `pending` 只表示本次权威查询没有终态，不允许丢原 ID。
- `accepted` 必须是原 content hash 和原 expected sequence + 1。高层再调用 `ConfirmRecoveryOperationResolutionAccepted`，通过普通完整 vault/HPKE/DAG/原记录确认，取得仅在 RAM 的确认结果，最终保存交唯一高层 owner。
- `closed` 是原精确目标的永久服务端收据，不能覆盖 accepted。只有高层已持久化明确关闭意图并完成本机 whole-state CAS，才退役原本机包。

普通 DAG opener 仍读取并验证完整来源、封套和历史。若已有受保护 `PriorBundle`/`MinimumSequence`，保持原 pin、全部已见 record 的 hash/sequence/完整编码和全局下界；当前响应不得删分支或退序号。auth-only 查询能在合法旧 rotation 产生的 DAG gap 后读取已经保存的 closed 收据；普通新恢复在同一 gap 下继续拒绝。它不修复历史，也不授予设备可信。

## 后续合法图与闭锁事实的一致性

本机 closed 收据永久拒绝同账号/代际的同 operation ID 或同全局 sequence 被任何后续 accepted 记录占用。完整原 pin、合法祖先、全部旧记录字节/sequence 仍须先验证；密码学有效不代表可以覆盖已知闭锁。核对覆盖 baseline、当前受信云图、journal/preparation 的完整依赖、新受限 owner 每次 vault refresh、原包查询/确认，以及 B3b 最终保护 CAS。

closed 约束只给出拒绝下界，不是权限节点、认证凭据或新的网络 wire。高层从已保护精确收据复制全部约束，normal opener 再复制其 slice；调用者之后修改输入不能松开已建立 owner 的历史门。合法非冲突扩展继续允许；冲突保持原包和 native 状态，不提前赋予可信设备。640 项/8MiB 保护状态边界保持，不能丢弃旧收据换取空间。
