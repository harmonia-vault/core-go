# 手机 Go 恢复原操作关闭首片

本片是 native-only Go 高层业务，未开放 UI、ABI、SDK、能力开关或新管理权限。只支持 sealed `transition-v2/old-recovery`；缺少旧完整清单的 recovered/intent/challenged 明确 unsupported，零 resolution POST。原三份 JIT 账号 helper/测试/文档保持不变，旧原签域和 journal 编码不变。

可用接口：

| Go 方法 | 边界 |
|---|---|
| `RecoveryDAGResolutionInfo()` | 读取当前精确目标的 metadata；无网络，不授可信 |
| `QueryDAGOperationResolution(ctx,registry,scope,currentCode)` | 用当前完整码创建本次受限证明，只查原目标 |
| `CloseDAGOperationOriginal(ctx,registry,scope,currentCode,expectedTargetHash)` | 显式确认当前目标 hash，先 CAS 保存关闭意图，再发同 ID resolve-or-close |
| `BeginDAGRecoveryAfterClosure(ctx,registry,scope,currentCode)` | 明确开始新 owner，完整 vault/HPKE/DAG 验证，保留原 pin、全部已见 records 和 closed 下界 |

这些方法需要现有本机 whole-state CAS/check 回调和精确 registry scope。先退役同原包的空闲 RAM owner，busy/异账号/异设备/异 scope 失败。旧 bearer 不用于认证，新的受限 bearer、恢复钥、完整码不进入持久状态。关闭 intent CAS 失败时，不取得新证明也不发送 resolution POST；native 基点失效或持久失败在锁外 Close 清进程材料。

保护状态新增独立 `recoveryDAGResolution`，包含精确本机 tuple、原 pin/bundle/global sequence 下界、单个 pending 计划和 append-only closed 收据。closed 和 accepted 不能在同 ID 或同全局 sequence 上矛盾。冷启动复验所有 accepted record 的 sequence，不只恢复 rotation head；所有旧 record 和收据不可删除/替换。OwnerEpoch 0 沿已有 S1/B1 合同合法，必须精确绑定当前 state epoch，旧收据不得来自未来 epoch。

结果区分服务器 `observation` 和本机 `localState/confirmation`。`pending`、未知网络结果、关闭响应丢失、CAS 失败都保持原包与 ID。普通取消仅取消当前调用。服务器 closed 后若本机 CAS 回应丢失，当次仍失败；下一次真实 native 冷读与原 ID 查询才能确认状态。若 query 观察到 closed 但本机没有持久关闭意图，保留 pending，仍需显式关闭确认。

accepted 分支保留原签包和原收据，先保存观察，再通过成熟完整历史/封套验证，最后把原 journal 的接受序号/Applied 和完整账本同一次 CAS 保存。这里的 Applied 仅是原包已确认，`TrustedDevice` 始终 false，不能跳过后续显式登记及 B3b Boot/Pull/final-CAS。

closed 分支把永久收据、全部已见原账本/序号、原包退役同一次 CAS 保存。普通 `OpenDAGRecoveryOwner` 不会因原包已清就隐式重开；明确新操作使用新 ID。后续签包的 before-prefix 可能短于已确认账本，两个 bundle 同原 pin 完整验证后，只允许逐 record 精确包含，并保留较长一侧与最大下界。退出保留已知 closed 账本，AccountClosed 不授予重新开始；普通旧恢复业务继续 gated，不能由 discovery 自动换来源 parser。

closed 最多 640 项且不驱逐；既有 whole-state 8 MiB 上限保持。容量、CAS 或服务端配额失败保持 pending/未知；不以清 tombstone 释放容量。当前只在未可信恢复 context 操作这些接口，设备已正式激活后的管理查询适配留后续。

验证与失败记录见交付的 `VALIDATION.md`。真正手机系统密封/CAS、UI/ABI/SDK、workerd 客户端联合和其它 journal 类型均未在本片验收，不宣称生产可用。

## 后续合法图与闭锁事实的一致性

本机 closed 收据永久拒绝同账号/代际的同 operation ID 或同全局 sequence 被任何后续 accepted 记录占用。完整原 pin、合法祖先、全部旧记录字节/sequence 仍须先验证；密码学有效不代表可以覆盖已知闭锁。核对覆盖 baseline、当前受信云图、journal/preparation 的完整依赖、新受限 owner 每次 vault refresh、原包查询/确认，以及 B3b 最终保护 CAS。

closed 约束只给出拒绝下界，不是权限节点、认证凭据或新的网络 wire。高层从已保护精确收据复制全部约束，normal opener 再复制其 slice；调用者之后修改输入不能松开已建立 owner 的历史门。合法非冲突扩展继续允许；冲突保持原包和 native 状态，不提前赋予可信设备。640 项/8MiB 保护状态边界保持，不能丢弃旧收据换取空间。
