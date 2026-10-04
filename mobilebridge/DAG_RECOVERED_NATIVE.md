# 恢复设备显式登记的原生 Go 入口

本片仅连接已验证的 B3a 业务，不开放 Flutter、MethodChannel、SDK 或公开 capability。登记原包被服务器接受也仍然是 `trustedDevice:false`；B3b 的正式 Boot/Pull 与最终本机 CAS 激活另行接线。

每次原生强认证后创建新的 `OpenAtomicWorkflow`，校验包名、固定 slot、平台 epoch 与 captured 完整密文，附加同一个不可序列化的 `NativeDAGRegistry`，再调用 `ExecuteDAGRecovery`。设备钥匙、受限会话 bearer 和恢复种子只留在原生或 Go RAM 中。调用结束正常 Close 当前 Workflow；取消或存储失败使当前 registry 永久失效，原生必须在锁外排空 Close。

## 四个命令

共同顶层字段为 `version:1`、规范 HTTPS `endpoint` 和字符串 `operation`。字段必须精确唯一，四个新命令的独立码参数长度均为零。

| operation | 额外字段 | 行为 |
| --- | --- | --- |
| `dagRecoveredEnrollmentChoices` | 无 | 返回当前完整验证的 sequence、recoveryHeadHash 和 environmentId/keyVersion 候选。候选不代表已经选择或登记。 |
| `sealDAGRecoveredDevice` | expectedSequence、recoveryHeadHash、selections | 前两者是候选的规范十进制字符串与小写 SHA256；selections 是严格 JSON 数组的字符串，1–16 项，每项精确包含 environmentId/keyVersion/role/expiresAt 字符串。角色只允许 ro/rw/admin，期限为规范非负十进制。必须明确选择，无默认全选、角色、期限或版本。 |
| `retryDAGRecoveredDevice` | operationId、contentHash | 先与本机已封存原包的 ID/hash 精确比较，再查询或提交同一原签包；不能重生 nonce、换 ID、换选择或重签。 |
| `dagRecoveredDeviceInfo` | 无 | 只读本机已保护元数据。冷恢复可显示 interrupted-original 或 accepted-not-device-applied，不能据此建立可信设备。 |

sequence 和 acceptedSequence 输出为十进制字符串。输出只含候选版本或原包 metadata，不含原签包、封套、变量、私钥、bearer、恢复码。intent/challenged 尚未形成原签包时 contentHash 为空；sealed 后返回成熟 journal 的原 hash。

`ok:false` 的 `ORIGINAL_RETRY_REQUIRED` 仅在成熟业务保留同一活 owner、后置 whole-state Check 仍成功且无取消/认证/权限/存储错误时返回。原生可保留 RAM owner 并让用户再次执行原命令。硬错误不能转成“已接受”；冷 owner 丢失也不能造新会话重投旧包。

## 锁和当前边界

现有 `VaultWorkflow.mu` 是单句柄的有界操作排空锁，仍覆盖网络请求以防 Close 与保存回调清钥竞态；它不串行其它认证句柄。Workflow 的共享业务状态锁、registry 锁和原生持久化锁不跨 HTTPS。Invalidate 不先取该排空锁，只取消当前记录；迟到网络返回必须经过 ctx、registry dead、保存失败和后置 Check 门槛。每次记录的 context 上限为30秒。

本片复用成熟环境权限、到期、generation、源证据、恢复 head、设备双钥和 CAS 验证，不实现新的密码学或服务器 DTO 信任。普通 WorkflowProfile 仍不包含这些命令；B3b 激活、封存原操作 resolve-or-close 和 UI/SDK 暂未开放。

验证只用合成环境与回环 HTTPS。Go 测试的 atomic AES provider 是 native 持久化适配证据，不代表已经验证 Android/iOS 强认证、ABI 或应用 UI。
