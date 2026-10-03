# 恢复后管理手机的 V4 批准业务

本入口用于已经显式登记、完成持钥 Boot、验签拉取并保存原生保护状态的恢复管理手机 E。来源保持原初始化根、公钥及连续恢复链，使用 `issuer-recovery-v1` / certificate 4，不能降级到 V3 或把恢复公钥当原根设备。原生层每次调用前仍须系统设备密码或强生物认证；Go 业务测试不替代 Android 认证验收。

## 原生业务接口

```go
result, err := workflow.ApprovePairingV4(ctx, mobileworkflow.ApprovalInput{
    PairingID: originalID,
    ShortCode: enteredCodeBytes,
    Selections: []mobileworkflow.ApprovalSelection{
        {EnvironmentID: selectedEnvironment, Role: "ro", ExpiresAt: "0"},
    },
})
result, err = workflow.RetryApprovalV4(ctx, originalID)
info, err := workflow.ApprovalInfoV4()
err = workflow.CancelApprovalV4(originalID)
```

明确选择沿用已有 `ApprovalSelection` 的环境、角色与期限验证。准备签包之前刷新当前权限，并用成熟 `PrepareEnrollmentProofV4` 检查每个环境的当前 Admin；新授权期限不得超过据以授权的 Admin。真实 BoringSSL SPAKE2 确认新设备、管理设备的精确 Ed/X 公钥、账号代际、挑战与 transcript，然后逐环境解开本机 HPKE 并为新设备封装钥匙。签包来源是已保护、已复验的 Proof3，服务器公钥目录不能建立信任。

`ApprovalResult` 与 `ApprovalInfo` 只含状态、原操作 ID、新设备 ID、选择、期限和序号等元数据。`approved` 且 `sequence == 0` 只表示服务器保存批准；只有原审批包上的新设备完成签名通过验证，并且完成序号真正原生密封后，才返回 `complete`。两者均不替代子设备自己的持钥 Boot、验签拉取和最终保护状态保存。

本入口当前需要已应用的直接恢复设备记录。非恢复 V2/V3 手机继续使用对应原入口；尚无完整本机受保护 V4 手机入网收据的上下文明确拒绝，不从目录猜来源。

## 原包保存与结果不明

可选 `pendingApprovalV4` 只保存完整公开签包、选择摘要、本地 epoch、状态与时间。逻辑配对操作 ID 与服务器生成的 PAKE 会话 ID 是两个字段；各自与原请求及已签 Context 精确绑定，不能互换。记录不保存短码、PAKE 临时私钥、密码、恢复种子、设备私钥或设备会话 token。短码只在当次成熟 PAKE 中使用，原生调用方须清理可控制缓冲区，不能日志或持久化。

按以下顺序执行：原签包 prepared 密封成功 → attempted 密封成功 → HTTP POST。任一保存失败均不发送。已接受但响应丢失时重启查原 ID；精确匹配原 Profile4、来源、两公钥、选择、签名、nonce 与 transcript，再密封 approved 元数据，不重新生成密文或授权。收到子设备完成签名后同样先密封完成状态；最后保存失败仍返回结果不明，重启继续原记录。

`CancelApprovalV4` 只清理尚未 attempted 的 prepared 记录，清理须保存成功。尝试过的请求可能在途，不能用空查询取消，也不能换角色、期限或新 ID 重发。未完成记录阻止普通值读取、共享写入和其它审批版本；允许原记录元数据、明确重试及退出。检测失权清理保护资料；墙钟回退不可重新开放原挑战。

## 本机证据与剩余范围

真实 TypeScript/SQLite HTTPS、真实 Go Ed25519/HPKE/AEAD 和 native SPAKE2 的六个必要场景全部通过：正常批准、prepared 保存失败、attempted 保存失败、approved 保存失败、已接受响应丢失、完成状态最终保存失败。每项均从真实连续恢复并显式登记的 E 开始，子设备完成双签后重新持钥 Boot，再以 Proof3 拉取唯一所选 RO 环境和正确明文。原包重试只提交一次；approved 不伪报 complete，最终保存失败不伪报完成。

命令：`mise exec -- go test -race -tags harmonia_boringssl ./acceptance -run '^TestMobileApprovalV4RealHighLevelJournalAndCompletion$' -count=1 -v`，主测试 32.79 秒，Go 总计 34.273 秒通过。`mobileworkflow` 全包 native race 4.648 秒通过，`go vet` 通过。

新高层还通过真正编译的正式 CLI4 联合测试：E 调用 `ApprovePairingV4` → CLI 的新设备双签完成（200 响应故意丢失为 504）→ CLI 原加密收据恢复 → CGO0 daemon 新持钥 Boot / Proof3 拉取 → RO 拒绝共享写入。管理者完成状态最终保存失败后仍保持 pending，重新打开原生保护上下文、原 ID 查询后才密封 complete。新增正式 CLI4 主测试 8.90 秒通过；原既有正式 CLI4 的 RO/RW 两条路径 9.34 秒通过，原断言保持不变。

同时重跑六场景、以上新高层 CLI4 与原既有 CLI4：三项主测试通过，六个保存/未知结果子场景通过，Go 总计 52.493 秒。测试辅助函数只增加可选审批回调；没有回调时沿完整原业务与断言运行，没有改原 17 个安全恢复场景。

首轮六场景因实现误把逻辑操作 ID 与 PAKE 会话 ID 设为相等而失败（18.824 秒），已分离两个原字段后重新运行全部六场景通过。不存在放宽签名或来源校验。

Android 恢复管理手机的系统强认证、V4 高层批准桥与界面尚待独立实际验收。本切片不增加 UI、CI、发布或部署，也不宣称生产可用。
