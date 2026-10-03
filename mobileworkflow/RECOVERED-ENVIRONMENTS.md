# 恢复后设备的环境操作

这是实验性 Go 高层业务切片。Android 原生桥、系统认证和界面尚未接入本页能力，不能据此宣称生产可用。

## 正式调用路径

设备须先完成连续恢复、用户明确选择角色的 cert4 登记、设备持钥 Boot、完整 proof3 Pull 及原生最终保存。随后由原生系统认证层调用现有 `CreateEnvironment`、`RotateEnvironment`、`RenameEnvironment`、`DeleteEnvironment`、`SetVariable` 和 `DeleteVariable`，无需另一个简化接口。

新建和轮换明确使用 `issuer-recovery-v1` 控制证明和 `/environment-changes-v3`。签名请求仍采用已验证的环境 change 和 origin 两签包、同一内容摘要与幂等请求库。重命名、删除和变量写删继续原协议域。旧 P2 日志保留原能力与原路由；不会自动升级成 P3，失败不会回落旧解析器。

所有共享修改必须在线。暂停、RO、失权、到期或未完成入网均不能写。历史证明只用于重验原请求，不提供当前写权限；发送和普通下发仍逐次检查当前授权。

## 恢复封套与原始固定根

恢复封套的当前接收公钥和代际只能来自完整验证并受保护保存的 `CurrentIssuerRecoveryEvidence`。候选控制证明还须与该当前恢复根一致。完整连续恢复链和原始初始化固定原根设备的 Ed/X 公钥；不会用服务器目录替换 Root、移动原设备 pin 或添加全局管理公钥。

新环境与每次轮换生成独立环境钥和当前恢复封套。轮换保留完整当前设备接收者、角色和期限，使用既有 HPKE、签名域和严格当前权限控制。只有历史上可解封的钥不等于当前 Admin 权限。

## 原生原请求日志

`originV2` 是既有受保护日志字段名。P3 记录另含明确的 `capability` 和独立 typed `recoveryControl`；旧 P2 字段不能装入第三版证明。完整原请求的密文、nonce、两签包、内容摘要、历史授权及完整证明须在 POST 前由 `SaveProtectedState` 原子密封保存。保护状态上限和原有 32 条环境日志容量限制不变。

重开 `New` 时从原保护根重新验证该历史日志，不发 HTTP、不由历史证明建立当前会话。用户重试同一 id 时先查原路由的精确状态和内容摘要；已接受请求不生成新的包或重新 POST。未知请求仅能重试原包，竞争冲突不自动换 id、重签或重封密文。

服务器接受后通过同一正式验签 Pull，检查原事务尾序号、所有内部写项及完整 origin，再确认应用。最后原生保存失败返回 `ErrAcceptedNotApplied`，内存记录也不得报告已持久完成；重开后仍保留原请求供查询与再应用。没有乐观修改本地权威值。

## 实际验证

本轮在独立临时源码快照验证，公开基础为 core `de7bb21`、server `02689b4`、workspace `14a27f9`，仅覆盖此候选切片。测试使用合成账号、合成值、本地 HTTPS 测试 CA、临时 SQLite 和真实 Go HPKE/签名；AES callback 模拟原生持久边界，不替代 Android Keystore 实测。

- `go test ./mobileworkflow`：通过，0.572 秒。
- `go test -race ./mobileworkflow`：通过，3.058 秒；同包 `go vet` 通过。
- `TestRecoveredMobileEnvironmentCRUDOriginalJournalAndFinalSave`：真实 HTTPS 普通测试通过，3.42 秒；native race 通过，12.04 秒（包执行 13.419 秒）。
- 实际链路：连续恢复 E → 显式 Admin 登记 → 创建环境成功响应丢失 504 → 原日志 New 查询恢复且无第二次接受 POST → 变量写 → 轮换最终原生保存失败 → 原包 New 恢复 → 重命名保留原值 → 删变量、删环境 → 重开验证。

本测试不读取宿主环境变量、真实凭据或旧签名私钥，不安装系统服务、不发送外部邮件。Android 此高层能力、跨端界面及原生持久边界仍未跑；持续恢复来源的后续 DAG 扩展也不属于本切片。
