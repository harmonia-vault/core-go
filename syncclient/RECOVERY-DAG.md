# 重复恢复与证书5客户端

本切片是实验性实现。协议 major2 与 `issuer-recovery-dag-v1` 显式协商；证书5、P4 来源账本及新 HTTP 路由分别解析，旧证书1–4不会自动升级。成熟原语和有界 DAG 校验来自 `cryptox`，客户端不引入新原语，也不把服务端设备目录当作信任根。

`OpenDAGRecoverySession` 接收完整离线恢复码、HTTPS 地址、账号代际和唯一原生加密 journal。它本地签一次恢复挑战，核验恢复钥匙签过的原根、完整初始化、已接受 DAG 历史及当前封套承诺，然后解开环境钥匙。恢复种子、派生私钥和受限 token 只在当前进程；`Close` 尽力清除它们。恢复成功仍是受限会话，不能直接进行管理授权。

`BeginTransition` 显示新的完整恢复码。`SealTransition` 要求完整重输，确认派生公钥相同，以新钥匙签服务器单次 nonce，并生成所有当前环境的新 HPKE 恢复封套。只保存不可变的公开签包，提交前先写原生加密 journal。`RetryTransition` 先查原 ID、原内容 hash；未知时只在原会话、原 nonce 仍有效的情况下重发同一包。完整封套与新公钥在服务端原子接受后才替换本机 RAM 钥匙。

`SealRecoveredDevice` 要求显式环境、角色和期限，产生本机双钥与环境封套的精确绑定；成熟 HPKE 解封成功后才能生成设备反签。`RetryRecoveredDevice` 只返回已验的公开接受记录和来源证据；它不会自动将手机标记为可信。调用者还须构建 `NewRecoveredDAGPinnedVerifier`，以当前设备签名完成 `BootDevice`、验签 Pull，并成功保存原生保护状态，才可开放业务入口。

`VaultDAGJournal` 固定使用 `recovery-dag-v1`，绑定 HTTPS 地址、账号、账号代际、本机 owner epoch、原 pin 和原包 hash。加载与保存在 Vault 锁内检查退出 tombstone 和 epoch，拒绝旧 owner 重建 journal；原包字段与 Attempted/Accepted/Applied 状态不能回退。账号退出、全局撤销与代际失效的既有清理会删除该 slot。新进程加载未知 journal 后不能另取 nonce 或替换原 ID；`QueryOriginalOperation` 只查原状态。显式 `ResolveOriginalOperation` 可确认原接受记录并密封结果，但保留新受限会话的 `RotationRequired`，不凭旧收据解锁管理。

`NewEnrollmentV5` 与 `NewApproverV5` 使用原生 BoringSSL SPAKE2。CLI 用 `pair --certificate-version 5` 选择该流程。受保护的原收据支持提交响应丢失后的恢复；普通 CGO0 后台可以持已接受设备钥匙 Boot/Pull，不能在没有原生配对实现时伪造入网。

真实联合测试使用合成邮箱与密码、本机临时目录及回环 HTTPS：首次初始化 A→恢复 B→再恢复 C→C 原生配对两个正式 CLI5（RO、RW）→普通后台 Boot、P4 Pull、原生 IPC 和隔离 shell fragment。覆盖真实恢复 HPKE、AEAD 解密、原请求响应丢失、原收据恢复、RO 拒写、RW 正常下发，以及保护状态重启与 owner 关闭。没有安装宿主服务、导入宿主环境或测试用户真实凭据；Android/iOS UI、Windows SCM 与该新恢复流程尚未联合验收。P4 环境 CRUD 与每环境授权管理控制已有显式 Go 接口；移动 P4 业务 journal/UI、全局设备撤销和 manager-reanchor 新 HTTP 流程仍须后续接线，不能据本纵链宣称完整产品或生产可用。


`EnvironmentControl` 在 P4 客户端只请求明确 DAG capability，HTTP `issuerEvidence` 按 P4 单一类型解析，内存 DTO 使用 `IssuerDAGEvidence`。`VerifyEnvironmentControl` 默认检查当前序号、期限和本机当前 Admin/KV/GG；只有明确 `true` 才重验历史业务 record，多参数拒绝。它复验本机固定初始化与 pin、完整 DAG 连续扩展及唯一 actor target，不能把服务器候选当成新的根。

`PrepareEnvironmentChangeV4` 为 create/rotate 生成原域 environment-origin；`SubmitEnvironmentChangeV4` 仅走 `/environment-changes-v4`。`EnvironmentStatusV4` 和 `ConfirmEnvironmentChangeV4` 校验原 hash、接受尾序号、同一 Pull 的完整环境/变量 checkpoint 与来源 origin。rename/delete 仍调用 `SubmitEnvironmentChange` 原域。P4 对旧 V2/V3 环境生产入口明确拒绝，不能自动降级。`ManagementControl` 只请求明确 DAG capability 并解析完整 P4 来源。

本切片的真实联合测试为 A→恢复 B→再次恢复 C→C 创建/重命名/轮换/删除 Z→原生 V5 PAKE 只授权 D 读取 Z，包含真实 HPKE、数据 AEAD、504 原包重开查询、native Save 故障的 accepted-not-applied 和暂停时签墓碑恢复原值。业务 record 仅在测试的 nativeVault/testadapter 中验证密封原包原则，没有把环境包写入恢复 checked journal。它不构成手机 SDK/Save 或移动 P4 环境工作流的验收。


## P4 每环境授权管理

`ManagementControl` 逐行验已接受历史双钥身份、签名授权、最高 GrantGeneration 与当前签包；唯一 actor target 必须是当前有效的 Admin。P4 控制必须 major2 与 `issuer-recovery-dag-v1`，旧 P2/P3 不会被提升或作为 fallback。`none`、过期或旧 KeyVersion 授权保留历史代际，不作为当前权限节点。

`PrepareGrantUpdate` 只接收用户明确选择的环境、既有可信设备、角色与期限，不接受目录公钥。签域仍为原 SignedGrant；只在完整当前 DAG 和精确接收者身份校验后产生 HPKE 封套。临时 Admin 不能授予更长或永久期限。P4 业务记录为 Version2 且必须保留 DAG capability；P2/P3 原 Version1 不会自动升级。记录和完整签包须由原生业务状态绑定 endpoint/account/generation/device/epoch，禁止放入 `recovery-dag-v1`。

P4 `Submit` 不允许无持久化屏障提交；须通过 `SubmitWithBarrier`，在原包与 Attempted 成功保存后才 POST。屏障失败为零 POST。发送前重新检查当前 Admin、版本、目标最高代际和期限；已接受结果只按原 ID、contentHash、sequence 查询，禁止新造封套或重签。`Confirm` 先核原 ID/hash/接受序号，再通过相同已验证 Pull 并成功保存 Engine 状态后才 Applied；它不以目标当前角色相同猜原请求成功。保存失败返回 accepted-not-applied。

`CheckManagementControlLowerBounds` 比较新控制与受保护历史控制，拒绝代际回退及同 GG 不同完整签包。它不存储业务历史。调用方必须原子持久化每个已见 subject 的 GG/fingerprint，不能因新投影省略该设备或返回 null/GG0 清除下界；历史 `true` 仅用于原 journal 复验，显式 `false` 仍检查当前序号与期限。

本批 nativeVault/testadapter 联合测试覆盖真实两次恢复、V5 PAKE、角色修改、丢响应原包重开、保存失败、暂停撤销、旧 KV none 后按最高 GG 恢复。该证据不是手机 SDK/业务 Save。P4 `PrepareOtherRevocation` 与 `RestoreOtherRevocation` 保持关闭；不能因为共用管理 DTO 而开放尚未接线的全环境撤销。
