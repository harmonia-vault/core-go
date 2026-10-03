# 手机连续恢复 DAG：S1 持久状态接线

本切片基于 core `06db7bb0c16312db8cf84511dd73284dbadfc7c8`，只实现 Go journal、手机整份保护状态的原子比较保存合同和关闭门槛。它没有连接恢复会话、原 ID 查询、证书5入网、P4 管理或原生/UI 能力。实验性软件不能据此宣称恢复产品可用。机器可读结果见 [本次证据](evidence/recovery-dag-s1-result.json)。

## 持久原包与既有消费者

`syncclient.CheckedDAGJournal` 共用既有原包验证。原 `validateProtectedDAGOperation` 的函数字节保持不变；完整签包、pin、endpoint、账号/代际、owner epoch、操作 ID 和 hash 仍绑定。原包不能更换，Attempted、AcceptedSequence、Applied 不能回退；原操作没有 Applied 时不能换成另一个 ID。不存在槽与损坏的空记录明确区分。并发冲突返回错误，不自动换 ID、重签或重试覆盖。

`NewVaultDAGJournal` 保留名称和 `VaultDAGJournal` 类型别名，仍使用唯一 `recovery-dag-v1` 固定槽。新增 `Vault.CompareAndSwapRecoveryDAGJournal` 在原 Vault 独占所有权内、同一 `Vault.mu` 下检查 `state-v1` 的 AccountClosed/epoch、原 journal 字节和保存。已有桌面/CLI journal 消费者因此也使用严格 CAS。旧 `SaveRecoveryDAGJournal` 保留兼容；没有改 `localkeys/state.go`、`EncryptedStateStore`、POSIX 或 Windows 实现，也没有增建另一个磁盘 owner。

手机 `recoveryDAG` 是完整 AES 保护状态中的可选记录，包含固定 profile、endpoint、账号/代际、设备双公钥、owner epoch 和原公开签包。它不保存 bearer、种子、恢复码、设备私钥或环境钥。记录不能与旧 Root、初始化、恢复/cert4、入网、审批、管理、撤销、写日志或授权缓存混用。`New` 重新验证；普通业务、旧恢复及旧入网入口拒绝该状态。没有旧来源自动迁移、服务端目录 TOFU 或布尔可信升级。

`RecoveryDAGPendingInfo` 只是 Go 元数据：原 ID、kind、hash、已保存接受序号和原核心 Applied。没有网络确认时是 unknown；即使原包 Applied，也始终 `trustedDevice=false`，不表示手机 Boot/Pull 或最终密封已完成。S1 不生成 expired、not-accepted 或 abandoned 本地事实，不删除未确定原事务来伪装完成。

## 整份状态 CAS 与失败关闭

`mobileworkflow.Config` 新增 `SaveProtectedStateCAS(expectedSHA256,next)` 和 `CheckProtectedState(expectedSHA256)`；这两个回调都必须存在。SHA256 只比较本次已认证完整明文快照，不是凭据或授权。

`mobilebridge.AtomicSealedStateStore` 要求原生提供 `CheckSealed(expected)` 和 `CompareAndSwapSealed(expected,next)`。bridge 将明文快照 hash 对应到本次成功解密的完整原密文；原生比较的对象是整份密文，而非单独 journal。epoch/AccountClosed 在这份已认证状态中。读取/OwnerAlive 也检查当前原生原字节；CAS 在提交瞬间再核一次，因此另一个 Workflow 退出后旧对象不能覆盖关闭状态。

保存下一状态成功之前不更新 RAM。保存或当前原生状态检查失败会立即锁死该 Workflow，撤销新 lease 并取消当前 context；需要重入业务锁的 owner Cancel/Close/清理延后到最外层操作解锁后，且只执行一次。这个规则也影响现有 bridge 的普通 `SaveSealed`/cert4 保存失败路径，不能只把 DAG 测试当作完整回归。`RecoveryRegistry.Invalidate` 仅执行即时失效；调用者必须在解锁后 Clear。

S1 仍不开放入口的条件包括：只有 `SaveSealed` 的旧 provider、缺任一 CAS/check 回调、没有明确账号代际、关闭/陈旧 epoch、混合 schema、持久失败或原包验证失败。内部 journal factory 不对外接收 signed packet；native 命令表、WorkflowProfile 和 ready gate 未添加 DAG 操作。

## 原生平台后续必须实现的边界

本次没有 Android/iOS CAS provider 或 SDK 验收。原系统认证存储只有原子替换/同步保存，原子替换本身不是 CAS。后续必须在同一固定 slot 的完整操作所有权下执行：核当前认证 epoch/活动状态、比较完整旧密文字节、写入并同步下一密文；Logout/Forget/删除也必须遵循同一所有权。callback 内读完、放锁、再普通写入不能满足合同。

Android 的串行 worker/busy 与 iOS 的串行 queue/epoch 只约束相应实例，不能证明跨实例 CAS。需要复用实际覆盖该 slot 的 whole-operation 锁；若没有跨 owner 锁，必须先补齐并实测。现 PIN 路径的 operation.lock 只可作为其自身完整操作所有权参考，attempt/limiter 锁不能代替整份 workflow 锁。iOS epoch NSLock 与活动状态回调的锁顺序也须显式设计，不能持同一非递归锁再次调用取锁回调。S1 不提前添加这些平台锁，也不声称当前平台已符合合同。

## 实际验证与边界

工具链为 Go 1.26.4、darwin/arm64，默认 build，无 `harmonia_boringssl` tag。

| 实际入口/范围 | 结果 |
| --- | --- |
| `mise run test-mobile-dag-s1`：syncclient、localkeys、mobileworkflow、mobilebridge、recoverysessions | 170 主测试 + 262 子测试 = 432 PASS；0 FAIL、0 SKIP；5 包 race 全部通过 |
| 本切片新增用例，包含于上行 | 12 主测试 + 31 子测试 = 43 PASS |
| `go test ./... -run '^$' -count=1 -timeout=90s -json` | 18 包编译通过；13 个测试二进制未执行用例，5 包没有测试；不是全仓测试通过声明 |
| Android/iOS/Gomobile、真机认证、原生 BoringSSL 配对、真实手机恢复 | 本切片未运行；默认 build 排除的 tag 测试不计入 0 SKIP |

测试覆盖保存故障不推进 RAM、原包重开、严格单调、两个 checked journal 的接受状态竞争、同 Workflow 保存/退出顺序、三个独立 Workflow 的退出/CAS/OwnerAlive 竞争，以及 bridge 真实 AES 封装后整份密文 CAS。持久层是合成、带互斥锁的 Go 原生接口替身；这不是手机系统认证或设备信任证明。

22 个 schema/绑定负例先把合成持久 slot 与候选 whole-state 同步，显式断言 CAS 期望匹配；直接调用目标 validator 时必须执行一次成功 native check、返回 `ErrDAGProtectedState`，且不能以持久失败 latch 代替拒绝。随后另验 `New` 也拒绝，普通 Login/Pull/旧恢复不能先发网络。此前一轮 432 PASS 中该组可被外层 snapshot mismatch 提前挡住，原日志保留，不能作为目标 schema 的独立证明；最终证据只使用修正后固定入口。

保存失败测试同时持有 session 与外层业务锁：失败返回、context 取消和新 lease 拒绝均必须在 Close 前发生；解锁后 owner 恰好清理一次。完整五包回归同时覆盖既有 cert4、registry、保存失败与生命周期消费者。

初次完整 race 在受限执行环境中因 synthetic httptest 不能绑定 `[::1]:0` 失败，保留该日志；正常 localhost 审批后重跑。没有改宿主网络/安全设置。测试只用公开合成向量、新随机本机测试钥和临时 slot；没有宿主真实凭据、个人路径或保护记录进入公开证据。

## S2 继续点

可复用 `DAGJournalStore`/`CheckedDAGJournal`、mobile 内部 `newRecoveryDAGJournal`、typed 元数据和双阶段 owner 失效。下一切片仍需严格绑定单次认证 lease 的活恢复 owner；不能跨认证长期持有某个 Workflow 指针，也不能在 session 锁内同步 Close。

进程被杀后必须保留原 ID/nonce/签包。若不持久 bearer，可完整当前码重新开启受限会话，只查询原包，明确区分已接受、未接受、仍不明；不能自动换 nonce、重签或把新会话 RotationRequired 清为 false。完整新码重输、显式 env/RO-RW-Admin/期限登记、证书5/P4、同一 Boot/Pull 验证及持久成功后开放可信业务均是后续工作。旧来源升级、P4 管理/reanchor 和原生/UI 接线仍关闭。
