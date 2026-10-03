# 重复恢复与证书5客户端

本切片是实验性实现。协议 major2 与 `issuer-recovery-dag-v1` 显式协商；证书5、P4 来源账本及新 HTTP 路由分别解析，旧证书1–4不会自动升级。成熟原语和有界 DAG 校验来自 `cryptox`，客户端不引入新原语，也不把服务端设备目录当作信任根。

`OpenDAGRecoverySession` 接收完整离线恢复码、HTTPS 地址、账号代际和唯一原生加密 journal。它本地签一次恢复挑战，核验恢复钥匙签过的原根、完整初始化、已接受 DAG 历史及当前封套承诺，然后解开环境钥匙。恢复种子、派生私钥和受限 token 只在当前进程；`Close` 尽力清除它们。恢复成功仍是受限会话，不能直接进行管理授权。

`BeginTransition` 显示新的完整恢复码。`SealTransition` 要求完整重输，确认派生公钥相同，以新钥匙签服务器单次 nonce，并生成所有当前环境的新 HPKE 恢复封套。只保存不可变的公开签包，提交前先写原生加密 journal。`RetryTransition` 先查原 ID、原内容 hash；未知时只在原会话、原 nonce 仍有效的情况下重发同一包。完整封套与新公钥在服务端原子接受后才替换本机 RAM 钥匙。

`SealRecoveredDevice` 要求显式环境、角色和期限，产生本机双钥与环境封套的精确绑定；成熟 HPKE 解封成功后才能生成设备反签。`RetryRecoveredDevice` 只返回已验的公开接受记录和来源证据；它不会自动将手机标记为可信。调用者还须构建 `NewRecoveredDAGPinnedVerifier`，以当前设备签名完成 `BootDevice`、验签 Pull，并成功保存原生保护状态，才可开放业务入口。

`VaultDAGJournal` 固定使用 `recovery-dag-v1`，绑定 HTTPS 地址、账号、账号代际、本机 owner epoch、原 pin 和原包 hash。加载与保存在 Vault 锁内检查退出 tombstone 和 epoch，拒绝旧 owner 重建 journal；原包字段与 Attempted/Accepted/Applied 状态不能回退。账号退出、全局撤销与代际失效的既有清理会删除该 slot。新进程加载未知 journal 后不能另取 nonce 或替换原 ID；`QueryOriginalOperation` 只查原状态。显式 `ResolveOriginalOperation` 可确认原接受记录并密封结果，但保留新受限会话的 `RotationRequired`，不凭旧收据解锁管理。

`NewEnrollmentV5` 与 `NewApproverV5` 使用原生 BoringSSL SPAKE2。CLI 用 `pair --certificate-version 5` 选择该流程。受保护的原收据支持提交响应丢失后的恢复；普通 CGO0 后台可以持已接受设备钥匙 Boot/Pull，不能在没有原生配对实现时伪造入网。

真实联合测试使用合成邮箱与密码、本机临时目录及回环 HTTPS：首次初始化 A→恢复 B→再恢复 C→C 原生配对两个正式 CLI5（RO、RW）→普通后台 Boot、P4 Pull、原生 IPC 和隔离 shell fragment。覆盖真实恢复 HPKE、AEAD 解密、原请求响应丢失、原收据恢复、RO 拒写、RW 正常下发，以及保护状态重启与 owner 关闭。没有安装宿主服务、导入宿主环境或测试用户真实凭据；Android/iOS UI、Windows SCM 与该新恢复流程尚未联合验收。P4 环境 CRUD、授权管理控制和 manager-reanchor 新 HTTP 流程仍须后续显式接线，不能据本纵链宣称完整产品或生产可用。
