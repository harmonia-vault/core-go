# B3b：恢复登记原包确认后的本机来源激活

这是实验性的 Go 业务入口。它完成已经确认的 `recovered-v2` 原登记到本机只读来源的转换，不开放手机客户端 UI、ABI、capability 或新的管理功能。

## 原包确认与设备可信分开

B3a 的 `AcceptedSequence > 0`、`Applied=true` 只表示原登记包已经按原 ID、哈希和接受序号确认。`syncclient.RecoveredDAGResultFromConfirmedOperation` 重新验证成熟 journal、双签登记和完整恢复 DAG，再从原包构造 pin、Accepted 和来源证据。它不访问网络、不生成 ID、nonce、封套或签名。

`Workflow.ApplyDAGRecoveredDevice(ctx, registry, scope)` 必须先验证受保护原包、本机设备 Ed25519/X25519 双钥、账号及代际。活 owner 仅在精确快照匹配且没有在途 lease 时退休；关闭 owner 在 Workflow 锁外等待。冷恢复可传 `nil` registry，但原包和 native CAS 门槛相同。

随后在独立候选 Engine 上执行正式 `BootDevice` 和 major 2 的 P4 `Pull`，验证完整来源账本、当前角色、期限、授权和持久序号。最后重新检查本机原快照、epoch、退出状态和当前 native hash，再用同一 whole-state CAS 保存来源、授权和云缓存。保存成功后才安装候选 Engine 并返回 `DAGRecoveredView.TrustedDevice=true`。登录令牌、恢复 bearer 或服务器目录都不能替代这条流程。

## 只读入口及保存合同

| 入口 | 用途 |
| --- | --- |
| `ApplyDAGRecoveredDevice(ctx, registry, scope)` | 完成已经确认的原恢复登记；不重发登记 POST |
| `RestoreDAGRecoveredDevice()` | 重新验证本机原来源、缓存和当前期限；到期清理通过 CAS 保存 |
| `PullDAGRecoveredDevice(ctx)` | 正式 Boot/Pull 后以候选状态和最终 CAS 刷新 |

新 `recoveredDAGDevice` 记录保存 `version`、明确 profile 和完整原 `recoveryDAGState`。历史 OwnerEpoch 不能大于本机当前 epoch。原 journal 的 ID、签名包、哈希和接受序号保留。兼容 Root 必须是原初始化双签确定的根；完整来源验证不允许改成服务器提供的根或 Managers。当前缓存必须满足原接受序号下界、完整账本和当前 grant checkpoint/fingerprint，缺账本或外部回滚拒绝。

本机 `dagCASRequired` 是黏性保存标记。加载 DAG 状态或首次 DAG 保存后，所有后续 `persist` 和 Logout 都用 whole-state CAS，不能退回普通 Save。字段被清空后标记仍保留。仅有该标记、账号 tuple 和空未可信状态时，已发布的 `LoginDAGAccountScope` 可以用 CAS 重新确认同一账号/代际；它不能换号、换代际或登录已退出状态。该 helper 三个已发布文件在本切片保持原字节。

## 失败、取消和退出

网络未知、迟到结果、Close/Logout 取消、CAS 冲突或保存失败均不得返回可信成功、安装候选或删除原包。网络和最终保存失败保留 `ErrAcceptedNotApplied` 与具体错误。CAS 失败闭锁当前 Workflow，取消在途资源；不能普通 Save 回退或反写旧状态。

如果 CAS 实际提交但回执丢失，当次仍失败且 `TrustedDevice=false`；重新读取真实 native 状态并完整验证后才能恢复。Close 只取消本次进程资源，不清持久配置；Logout 用 CAS 清信任与云缓存，保持 AccountClosed 和黏性保存要求。当前授权失效由成熟 Boot/Pull 分类判断，再清同账号来源。单纯网络故障不能当撤销。

候选和返回值只含当次明确 metadata/只读 View。原包、设备钥、环境钥不从这些入口导出；受保护状态不保存密码等价 hash、登录令牌、受限恢复 bearer 或恢复种子。

## 验证与边界

定向任务：`mise run test-mobile-dag-applied-components`。真实联合入口是 workspace 的 `TestMobileDAGRecoveredApplyHTTPS`，使用合成账号、真实 TS SQLite HTTPS、真实恢复 HPKE 与 Go native AES/CAS 测试适配。它覆盖 JIT scope→B1/B2/B3a→正式 Boot/P4 Pull→最终 CAS→冷重开、缓存回滚、离线到期，以及当前签 none 后清理。

Go whole-state CAS 与 native AES 测试适配不能证明 Android/iOS 系统认证或 SDK 保存；本切片没有模拟器、真机或 VM 验收，也没有开启 UI/ABI/capability。恢复后的 P4 管理、审批和变量写由后续独立业务接线承担；旧业务入口仍拒绝新来源。软件不能宣称生产可用。
