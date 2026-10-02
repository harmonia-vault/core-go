# HTTPS 同步与受保护入网

客户端使用 HTTPS 和逐请求账号代际/设备绑定，禁止重定向携带会话。通知只唤醒持久化序号拉取，不能直接提供权威值。设备登录不等于可信；可信设备通过精确双公钥的持钥挑战换取设备会话。共享数据只在线提交，接受成功后仍走相同验签拉取路径。

## 多管理设备 v2 入网

`NewEnrollmentV2(EnrollmentConfig)` 返回独立控制器；`Begin/Poll/Advance` 返回 `PairingStatusV2`，`Receipt()` 返回 `EnrollmentReceiptV2`，`Complete()` 返回带 `Receipt/Sequence/Verifier` 的 `EnrollmentResultV2`。控制器只访问 `/v1/accounts/:id/pairings-v2`；开始与每次状态都必须显式有 `certificateVersion:"2"` 和 `capabilities:["issuer-proof-v1"]`。不支持时拒绝，不改用 v1。

真实 SPAKE2 双向确认冻结本机新设备和管理者的精确 Ed25519/X25519 公钥、账号代际、用途、会话、nonce、期限和 transcript。随后先验证已确认管理者的 v2 签名，再验证完整逐环境签发者证明与全部 HPKE 封套；新设备签署相同证书后才可取得回执。短码、PAKE 临时私钥、密码和登录凭据均不进回执。

完整证明、双签及本机精确身份以机器保护保存。`ResumeEnrollmentV2` 仅从同一回执查询结果并幂等提交原签名，不恢复短码或 PAKE 临时状态。HTTP 结果不明返回 `ErrEnrollmentPending`；最终状态必须逐项确认同一完整双签对象。挑战过期后，已完成历史回执仍可验签，但不会恢复过期或撤销的当前权限。

`NewPinnedVerifierV2(IssuerPinnedTrust)` 接受受保护的完整回执、本机精确公钥与接收私钥，没有全局 `Managers` 参数。它复验本机 initiator 签名和管理者签名，再生成逐环境、逐 keyVersion 的 `IssuerBindings`。当前授权和历史作者授权只在已证实来源内验签；未知环境、未知版本、缺历史证明和目录中新钥匙保持拒绝。证明中的恢复公钥不会输出为 `RecoveryTrust`，恢复签名种子不能用作 vault 钥。

批准管理者必须先使用本地既有 `PinnedIssuerRoot` 和真实 PAKE `ConfirmedEnrollmentAnchor` 调用 `cryptox.SignEnrollmentApprovalV2`，验证来源图后才签名。仅从服务器复制 root 或只签 proof hash 都不够。服务器批准和最终完成仍要事务重查当前精确 Admin、期限、代际和版本；历史可验签不代表当前仍可管理。

既有 `NewEnrollment/ResumeEnrollment` 与单管理者 `NewPinnedVerifier` 是严格 v1 入口，不吸收 v2 未知字段、不扩大单一 pin。CLI 新配对明确使用 v2，已有 v1 待完成回执仍以旧域恢复。完整数组与边界见 [签发者证明](https://github.com/harmonia-vault/protocol/blob/main/docs/ISSUER-PROOF.md)。

## 合成验证

- `mise run test-issuer`：A/B 历史真实 AEAD/HPKE、逐环境来源、精确本机双钥、过期与撤销、降级/未知字段/超限、同一已完成回执查询。
- `mise run test-native-enrollment`：固定成熟 BoringSSL 真实 v1/v2 SPAKE2/TLS，正确码、错误码、能力降级和接受后连接结果未知的恢复；需按 pairing/README 构建本机静态库。
- `mise run test-native-enrollment-race`：上述 Go 控制器状态的 race detector。
- 仓库根 `mise run test/test-race/cross-compile`：全部 Go 回归与三平台默认关闭原生配对的编译。

当前来源图只支持同环境、同密钥版本的授权链。非根新建环境或跨版本轮换尚需签生命周期来源扩展，缺证据时拒绝。测试只用公开合成账号/密钥和隔离目录；编译不是平台运行验收，也不是安全审计。实际手机多管理批准界面、Android/iOS/Windows 原生完整流程的验证由相应组件记录；不能据此宣称生产可用。
