# 首根手机批准 CLI 的 Go 原生业务

本切片只实现已经确认的首根手机作为管理者。原生调用层必须先完成系统设备密码或强生物认证，再从自己的 AES 保护文件取得设备钥与业务上下文；服务器管理者同意、登录成功或 Dart 输入都不能替代本机认证。当前没有新增 Flutter 界面或自动安装服务。

## 窄接口

```go
result, err := workflow.ApprovePairing(ctx, mobileworkflow.ApprovalInput{
    PairingID: originalPairingID,
    ShortCode: enteredCodeBytes,
    Selections: []mobileworkflow.ApprovalSelection{
        {EnvironmentID: selectedEnvironment, Role: "ro", ExpiresAt: "0"},
    },
})
// 结果不明时明确查询/重试同一个ID，不再输入短码或改变选择：
result, err = workflow.RetryApproval(ctx, originalPairingID)
info, err := workflow.ApprovalInfo()
```

`Selections` 必须明确指定 1–16 个不同环境、`ro/rw/admin` 角色，以及规范 Unix 秒字符串或表示直到撤销的 `"0"`。拒绝过期时间、未知角色、重复环境与超限。排序后的环境/角色/期限和原配对 ID 以本地域摘要冻结，摘要不是新的密码派生或密码学原语。

`ShortCode` 为八位数字字节切片，标记为不可 JSON 序列化。它只进入本机固定成熟 BoringSSL SPAKE2。调用方不得写日志、发给服务器或密封保存短码；结束后清理可控制缓冲区。Go 运行时不能保证所有历史副本抹除。

`ApprovalResult` / `ApprovalInfo` 只返回状态、原配对 ID、新设备 ID、明确选择、期限和序号等元数据，不返回会话、封套、签包或钥匙。`approved` 只表示服务器保存管理者批准，设备仍未完成可信入网；只有核验新设备对同一证书的签名和服务器 `complete` 序号后才返回 `complete`。

旧 `ApproveDevice(context.Context,string)` 保持关闭，不能把旧字符串入口猜成新的完整审批意图。恢复、其它管理手机作为审批者及真实界面接线由后续切片处理。

## 精确根来源与 PAKE

首初始化被服务器确认接受后，保存其原 proposal 中的精确 `InitialAuthorities`。审批必须找到对应初始环境、keyVersion 1、grantGeneration 1、永久根自签 Admin；当前已验 pull 的授权必须与该原始签包摘要完全相同。不能从当前 self-signed grant、服务器公钥目录、命名规则或恢复公钥猜初始来源。缺新字段的旧实验上下文继续可执行已有业务，但审批明确拒绝，不重置账号。

调用先刷新当前权限，然后 GET 原 `/pairings-v2/:id`，冻结账号代际、用途、短时挑战、会话及本机管理者的精确独立 Ed/X 公钥。双方上下文中的新设备公钥也进入 PAKE 身份与 transcript；新 CLI 须独立检查自己的公钥。每次响应必须明确共同支持 `certificateVersion:"2"` 与 `issuer-proof-v1`，缺失或改变均拒绝。

`syncclient.ApproverV2.Confirm` 在一次操作内完成 manager SPAKE2、签名公开中继和双方 HMAC 确认；短码、通道钥和临时私钥不可恢复或持久化。确认后再次刷新当前精确 Admin，逐环境解开本机 HPKE 封套，重新包给新设备接收公钥，签署明确角色和期限授权。完整证明从本地初始来源重建，使用本地受保护 Root pin 和确认锚调用强预签助手，不能盲签服务端摘要。

服务器批准及新设备完成仍逐次、同事务检查当前授权。保留历史来源不代表管理者现在未撤销。新建环境、跨密钥版本和非根来源没有此切片所需初始证明，明确拒绝，不扩大根或恢复公钥的权限范围。

## 原生日志与未知结果

完整管理者签包、原配对 ID、选择摘要、本地 epoch、创建时间以及状态放在可选 `PendingApproval` 中，不含短码、PAKE 临时私钥、密码、恢复码或设备会话 token。设备会话由已有 Client 内部封装；重启可以重新持钥 boot，但只查或重发原签包，不能改变原 transcript、nonce、id、封套或角色。

首先真正完成 prepared 记录的原生 AES 保存，再把 attempted 标志真正密封，才允许 HTTP POST。任一步保存失败都不上传。未接受时明确重试原字节；已接受却丢响应时先查原状态，精确比较完整证明和管理签名，不重新生成密文。收到新设备双签完成时，先密封完成签名与序号再返回成功。

未解决记录阻止普通值读取与共享写入，元数据、明确原 ID 重查和退出仍可使用；已有自撤销门槛优先。新的自撤销不能绕过审批 pending 门槛。设备或账号失效清信任资料、初始来源及审批记录。源码入口不能以登录自动恢复旧权限。

`CancelApproval(id)` 只允许清理确定尚未尝试发送的 prepared 记录；清理也须原生持久成功。已经尝试、结果未知或已接受的记录不能靠一次空状态查询取消，因为原请求可能仍在途。当前服务端没有审批终止栅栏；到期、失权或无法证明接受结果时仍保留 pending 门槛，需要原状态明确完成或显式退出处理。取消本机操作不等于撤销服务器授权。

## 实测与未跑

本机 Go 1.26.4，固定 BoringSSL SPAKE2 profile 保持不变：

- `mise run test-native-approval`：7 项主测试、27 个子测通过。真实 manager↔CLI SPAKE2、HTTPS、Ed25519 和新设备 HPKE 解封；prepared/attempted 两次保存门槛；已接受与未接受的未知结果恢复及原字节重试；只有 C 双签才 complete；错误短码、换管理钥、代际/用途/能力替换、缺初始来源、未知环境、角色/期限、当前来源变化、日志篡改和审批/自撤销冲突均拒绝。
- `mise run test-native-approval-race`：通过，2.157 秒。检查 Go 控制器和原包日志状态；不代表原生 C 实现经过独立并发审计。
- 原生 AES 保存由隔离测试替身模拟真实成功/失败顺序，不算 Android Keystore 审批运行验收。现有 Android 首根/CRUD/自撤销证据由 mobilebridge/workspace 分别记录。

真实 Android 管理者→macOS CLI→TypeScript/SQLite 的跨端审批、本机系统认证到签包的完整新桥接、取消终止栅栏、全部管理手机及生产审计尚未由本组件验收。不能宣称生产可用。
