# 手机连续恢复 B2 v2：有限 Go 接线与旧入口互斥

实验性安全软件。本片只接 `old-recovery / continuous` 恢复 authority transition；没有打开手机能力，没有证书 5 设备登记、UI、SDK、P4 或服务端协议变更。

## 行为

B1 的 typed RAM owner 跨独立认证 Workflow 保留受限 session。B2 增加 Go-only `BeginDAGRecoveryTransition`、`SealDAGRecoveryTransition`、`RetryDAGRecoveryTransition`。每次仍附着当前完整保护快照、账号/设备/epoch，排空 callback 后分离，闲置 registry 不持 Workflow/provider。

Begin 先以 whole-state CAS 保存原 intent，再请求 challenge；准备新公钥也先 CAS 成功，才返回新码。完整重输经新公钥匹配后生成一次 nonce 签名原包，并在单次 CAS 中将 prepared 提升为 sealed。网络未知结果仅对明确 transport/408/429/5xx 暂时错误保留同一个 RAM owner 与原 ID/原包；409、认证拒绝、协议或字段错误，以及持久化或身份错误立即 invalid/cancel，锁外 drain/Close。

重试先查原 ID；未接受才在原 session 与原 challenge 条件下提交同一签包。服务端接受后，恢复 vault 证明与 Applied durable CAS 均完成，才允许封闭方法更新 owner 的恢复 Ed/X/head。原 5 分钟 deadline 不续期，challenge 期限只能缩短。旧 cert4 Advance 与 CheckedDAGJournal 不放宽；readonly B1 出错仍 retire。

冷启动丢失 RAM owner 时，intent/prepared 保留为明确中断记录；不自动换 ID、nonce、基点或认定 expired。sealed 原包仍可用 S2a 完整当前码新受限会话查原 ID；新会话 RotationRequired 不被旧 Applied 清掉。[严格 schema 与 closure 缺口](RECOVERY-DAG-B2-SCHEMA.md) 单列。

## 最终验证

实际基线为 core `dc28eb87` + 原字节 B1 overlay、workspace `92853660`、server `d27fb2a9`、protocol `3168864b`。B1 随后公开到 `d02f6a53`；本结果不追认该提交中其它增量已在本次运行。

| 检查 | 结果 | 范围 |
| --- | --- | --- |
| 定向 Go race | 108 PASS、0 FAIL | 冷 schema、不可变 intent、三阶段 CAS 故障、reopen、并发 owner、整体 8 MiB、AccountClosed、受控换代 |
| 受影响四包 race | 574 PASS、0 FAIL | syncclient、mobileworkflow、mobilebridge、recoverysessions；含现有 S1/S2a/B1/cert4 保存失败/registry 回归 |
| v1 真实 HTTPS/SQLite | 原源码 3 场景 PASS；v2 未重跑 | 保留原证据，不追认为本次两处 gate 修复后的实际场景 |
| vet | PASS | 上述四包 |
| Go 消费者编译 | 18 包、0 测试，PASS | 默认 build，不代表 JNI/ObjC/真机 |

v1 原源码的三个真实场景分别为：

1. 跨多次 Workflow 准备→拒绝再次显示→拒绝错误完整码→正确完整重输→sealed→接受→Applied CAS→受控 binding 换代。业务 challenge/submit 为 1/1；再次 retry 只 refresh。
2. 提交已接受但响应丢失；同 owner 查原 ID 后注入 native CAS 失败，立即 retire 且保护字节不变；完整当前新码冷查询并持久确认原包，新受限会话 RotationRequired=true。业务 challenge/submit 为 1/1。
3. challenge 响应丢失先留 intent；同 ID/同基点重试得 prepared；清 RAM owner 后冷启动明确 interrupted，Open/Query 均不发新 HTTP、不改保护字节。业务 challenge/submit 为 2/0。

计数按 owner-open、prepare、原查询/提交、冷查询分阶段，见 [机器证据](evidence/recovery-dag-b2-result.json)。fixture 账号注册/初始化属于场景准备，不计入 B2 业务计数。全部流程没有恢复设备登记、Boot/Pull 后设备可信或 CLI 管理。

## v2 审阅发现与窄修

v1 测试通过后，独立审阅发现 `recoveryOnly` 和 `mobileEnrollmentGate` 只检查 sealed `RecoveryDAG`，遗漏 preparation。同实例合法 Login 仍在 RAM 时，旧恢复 Begin 能越过 gate 进入 HTTP；旧 RecoveryInfo/EnrollmentInfo 也会把 preparation 当成 none。v1 候选因此被阻止发布，不能因原测试 PASS 忽略该缺口。

v2 仅在这两个 shared gate 各补一项 preparation 检查。新增组件先实际跑未修代码得到 21 FAIL，再修后得到 21 PASS：intent/prepared 各七个同实例旧入口、两个冷 Info，含父节点。两阶段各一个合成 Login 前置之后，旧入口新增 HTTP、ordinary Save 和 CAS 均为零，完整保护字节不变。

组件实际调用 `Workflow.Login` 并验证有效返回值，完整合成码先通过格式校验，公有准备材料经既有严格 CAS adapter 保存；不靠 missing login、坏码或 stale snapshot 提前挡住目标 gate。它没有新增 TS/SQLite 场景，也没有把私有 fixture 装配当作 Open-owner/Begin-transition 或系统认证验收。完整受影响四包 v2 race 为 574 PASS、0 FAIL；其中定向组件 108 PASS。原22文件冻结、修前失败日志和三份精确修前源码均保留。

## 原始失败与限制

最初定向测试有字段名编译错误，并误选 all-admin 公有向量；第二轮负例替换值与合成向量原 session hash 相同，导致目标负例失败。均保留原日志，修正测试后才形成最终结果。首轮三个 HTTPS 场景通过后，又收紧重复 Applied 的原 session/新公钥检查，并重跑固定三个场景；随后进一步将 B2 保活错误严格限定为传输/408/429/5xx，409/认证/协议错误 retire，再按最终源码完成相同有界验证。每轮保留原日志；首轮 HTTPS 另有源码 inventory，最终运行绑定最终源码 inventory。早期失败组件未保留逐轮完整源码快照，只作诊断历史，不把旧 artifact 追认为新源码。

尚未验证 native ABI/全 writer CAS、SDK 认证/后台/Logout/Forget registry 接线、证书 5 显式 env/role/expiry 登记、Boot/Pull、P4、服务端 terminal closure。没有改 native/UI gates，没有真实手机或模拟器测试；不能将本片 PASS 合并为恢复产品闭环。

验证入口：core `mise run test-mobile-dag-transition-components`、`mise run test-mobile-dag-transition`；workspace `mise run test-mobile-dag-transition-https`。全量新失败日志与精确源码 inventory 留在私有 review 供独立审计，公开证据仅哈希和脱敏计数。
