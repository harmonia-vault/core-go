# 原生进程内恢复会话生命周期

本包不认证、不签名、不联网、不存储文件。`mobilebridge/recovery_registry.go` 已将它接到 typed `mobileworkflow.RecoverySession`，可信 Kotlin 插件独立持有 registry，每次真实 CryptoObject 强认证和受保护上下文校验后才 lease。Handle/owner/私钥没有 MethodChannel 或 Dart 入口。连续恢复 Android 三阶段同源全部通过，含最后seal失败、原cert4登记恢复与直接E批准正式CLI4；完整证据见[RECOVERY_NATIVE.md](../../RECOVERY_NATIVE.md)；不将旧 V2/V3/管理结果计入本恢复证据，默认 gateway 和整体 ready 仍关闭。

## 接口与绑定

EdOwner 只提供幂等 Cancel/Close，引用成熟 Go typed session；没有 raw key、任意 Sign 或序列化。Handle 仅索引同一进程 registry，fmt 固定 opaque，Marshal/Unmarshal 拒绝；随机 handle 不是认证凭据。每个 namespace/slot/HTTPS endpoint/device EdX 固定 scope 只持一个 owner，不持 Device、完整 Workflow、原生 AES 钥或恢复 X 私钥。

Binding 必须来自 typed Session 与本次 Go 已核验的保护 record，不能由 Dart、文件 header 或服务器目录替代。它包含 scope、SessionEpoch（0 合法但精确匹配）、AuthorityHeadHash、RootDeviceID、account/gen/recoverygen、root EdX、recovery EdX、精确 InitializationProposalHash、随机 sessionHash、ExpiresAt 和原 transition ID/25 域摘要。只允许 transition 从 none 到原 id/hash、期限收紧，其余不可变化。

Registry.Run 只比较结构和生命周期，不能替代 Android 认证。Kotlin 必须先完成新的 CryptoObject、解包 72B 材料，Go 验证独立 AES state 后才 Attach。Go AttachRecoverySession 再严格核对同 record 的全部绑定；本包没有 auth bool，也不导出 lease 给 Dart。

Monotonic deadline 取原 deadline、5 分钟上限与 owner ExpiresAt 的较小值；原挑战绑定后最多125秒且只缩短。typed crypto 签名仍以成熟120秒挑战上界为准。到期计时器在没有新调用时也主动 Cancel/Close；并行操作和 busy 替换拒绝。lease 只在一次 Run 中有效，结束不关闭正常 owner，等待下一次独立强认证。Clear/Close 都取消 active context、同步幂等退役，dispose 不可重新 Install。

## 关闭与中断

普通 Workflow.Close 只 detach owner 并清本次设备/状态材料。原生认证取消、认证失败、保存失败、logout、失权、回拨、expiry、dispose 都退役 registry owner。原签包同步密封后 typed Go 主动关闭旧 owner；unknown 保留原 journal 语义。Run 保留原 typed 错误并与取消 error join，不把 AcceptedNotApplied/Pending 隐藏为普通取消。

App 杀死后 RAM owner 丢失，AES 文件不能重建旧 Ed；明确中断恢复才重新输入完整有效码针对原受限 token/hash/id/nonce Resume，不能换会话或延挑战。正常完整新码回填不增加第三个旧码表单。完成轮换的新 owner 也仅短时 RAM，仍 restricted，必须明确环境/角色/期限登记才可能最终 trusted。Begin/Complete 的接收私钥当次清除。

## 验证

合成生命周期测试覆盖不可序列化/旧 handle 重用、身份及 Epoch/head/rootID 绑定替换、TTL 主动退役、原 transition/期限收紧、busy/logout/dispose 取消 active lease、Install 失败清 incoming owner、新进程拒旧 handle，以及退役时保留原 pending 错误。它们不模拟系统认证成功。固定归档中普通/native bridge race、正常 AAR/Kotlin 构建已通过；Android 同一固定产物三阶段PASS94.475秒/30提示，实际强认证取消、密封前失败、unknown transition、跨进程完整新码、最后Applied seal失败/原ID登记恢复、可信E与V4正式CLI4跨端均通过；不包含第二次DAG恢复或PIN。

复现基础测试：core-go 目录 `mise exec -- go test -race ./mobilebridge/internal/recoverysessions -count=1`。原生三阶段使用 `mobile/tool/native-recovery-test.py` 与明确固定 snapshot、独立 AVD/test 包/合成 PIN，所有自身资源 finally 清理；不发布二进制、不自行提交或推送。
