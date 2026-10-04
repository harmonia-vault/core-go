# P1 恢复登记后的正式本机激活

这是 B3a 四命令之后的封闭 Go 原生接线。`profile` 的真实固定值是 `issuer-recovery-dag-v1`。普通 WorkflowProfile、Flutter/MethodChannel、ABI/SDK capability 暂未开放；本文的 Go 结果不能替代手机系统认证或 UI 验收。

## 三个入口

共同 command：version数字1、规范HTTPS endpoint、operation字符串和精确额外字符串字段。独立完整码 buffer 在本三命令中长度为0。每次新的已强认证 AtomicWorkflow 和 captured 全密文，附加同 namespace/slot/platformEpoch 的 opaque registry，继续执行唯一 ExecuteDAGRecovery。

| operation | 字段 | 门槛 |
| --- | --- | --- |
| applyDAGRecoveredDevice | operationId/contentHash | 网络前精确匹配已保护的 recovered-v2 原包，acceptedSequence>0、originalConfirmed=true；唯一成熟 Apply 退休原RAM owner，正式Boot→P4完整验证Pull→最终whole-state CAS。没有CAS成功不成为可信。 |
| restoreDAGRecoveredDevice | 无 | 只从已存完整本机来源调用成熟Restore；复验source/pin/checkpoint并进行离线到期清理CAS，不借普通或legacy View。 |
| pullDAGRecoveredDevice | 无 | 从同一个DAG来源再次freshBoot/P4 Pull与最后CAS；每次验证generation、设备授权、环境权限、期限、完整历史，不降级parser。 |

首次Apply失败保留原包；重新认证仍对原ID/hash执行Apply。若来源已经实际保存但保存回执未知，重新打开本机captured完整密文并调用Restore重新确认；已完成页面使用Restore/Pull，不重新封登记包或用Apply伪造新ID。

## 成功数据

只在这三个成熟成功结果为TrustedDevice=true，且ctx/registry/saveFailed/后置完整native Check全部通过后，外层及data的trustedDevice才为true。data包含version/profile、operationId、contentHash、acceptedSequence字符串、binding及view。

binding包含本机已保护且与成熟结果精确一致的accountId、accountGeneration、deviceId、checkpoint字符串。view包含deviceId、checkpoint字符串、experimental:true以及environments数组。每环境为id/name/role（RO、RW、Admin）/variables字符串字典；变量来自成熟已授权View，可供本用户读取页面展示，禁止日志、统计或报错回显。没有设备私钥、会话bearer、恢复码、原签包或HPKE封套。

失败、取消、未知和存储失败不返回trusted成功DTO，也不假设活原owner还在。原包保存与source激活是不同事实；B3a accepted-not-device-applied仍为false。当前撤销触发成熟失效/清理流程，不能拿冷来源继续返回旧变量。Restore是离线本机缓存复验，不表示已在线确认远端的当前状态；需要最新状态时使用Pull。

## 冷状态分流

dagRecoveredDeviceInfo先由成熟业务验证DAG状态。none或interrupted-original不读取不相干的transition Pending；它只投影已验证的准备ID/phase、空contentHash、unknown及falseTrust。真正pending-original或accepted-not-device-applied仍要求recovered Pending精确ID/hash/seq/原包确认匹配。空hash不能retry登记；原RAM owner仍活时只能重试相同seal选择。

cancelDAGRecoveryOwner仅native本地取消；它不表示服务器闭锁，不清原包。冷sealed同ID查询已有queryDAGRecoveryOriginal，但本片没有新增resolve-or-close或recovered闭锁入口。

## 有限实际证据

新 B3b 主链通过真实回环HTTPS/NodeSQLite：挑战响应504后的原intent续办、真实HPKE已确认登记仍false、正式Boot/P4后的最后CAS故障保持restricted、同原ID完成最后CAS并返回真正授权变量、冷Restore零网络、freshPull、真实Admin签none后当前Boot拒绝及冷source清理。Go AES/CAS provider只证明原生持久化适配，未跑SDK/设备认证/UI。第一轮新增测试未用import编译失败和vet相对路径setup失败保留。

前一B3a文档仅描述其四命令片；当前额外三命令以本文为准。设备写入、管理、UI/cap开放仍单独验收，不经legacy兼容快捷路径。
