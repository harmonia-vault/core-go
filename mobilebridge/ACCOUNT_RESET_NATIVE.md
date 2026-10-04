# P3 原生账号重置接线

本实现仍为实验性封闭 native 接口，不注册 MethodChannel，不改变 Flutter 能力或宣称生产可用。协议、密码 SHA256 和服务端响应检查全部复用 `accountreset`，未修改该冻结包。服务端仍负责邮件证明、单次挑战、账号 generation 原子切换和永久首号策略。

## 入口与原请求

Android 原生 `begin(endpoint, proof)` 明确开始新流程，持有一个 `NativeAccountReset`，先查询邮件 proof。原生 namespace 来自固定包名和 workflow 槽；CA 只来自系统信任根或构造器固定测试 CA。proof 缓冲消费后清零，不写入日志、URL 或 Dart 持久状态。

用户明确确认后，`prepare(password, "DELETE_OLD_VAULT")` 消费密码缓冲并只创建一次原 `accountreset.Attempt`。输入原文仅 SHA256，不增加客户端 KDF。之后 `query()` 与 `complete()` 不再接收密码、地址或 proof，不能用新值替代原请求。

原 RAM 丢失后的入口是 `beginQueryOnly` / `OpenNativeAccountResetQuery`：该 owner 永久禁止 Prepare，只有元数据查询。不得将冷恢复路由至新流程工厂。当前没有持久原 payload journal 或自动 cold Submit。服务端邮件申请仅返回 `accepted:true`，不能据此证明重启后任意粘贴的 proof 属于新申请；另起重置应重新申请邮件证明，不能称为原事务重试。

申请邮件继续使用既有 `accountreset.Client.RequestProof`；本片原生消费者从完整合成邮件 proof 开始，申请邮件与界面入口尚未开放。

## Query、原生槽与提交

每次 `BeginCompletion` 先按原 proof Query；严格校验已经由 `accountreset` 完成。成功才产生同 RAM owner 的单次完成对象，最长 120 秒，不表示云授权或设备可信。pending 查询不提交；complete 查询也不会重新 POST。

Query 成功后，P3 worker 同步清理普通 recovery RAM registry；随后用既有 `cancelDAGRecoveryOwner` 的完成回调等待 DAG worker 真正 Close 和 owner 排空。单纯 `invalidate` 或 `isBusy=false` 不作为排空证据。

本片只接两种本机状态：

- 新手机：在固定 `NativeSlotOwner` 文件锁和完整快照下确认所有已跟踪 system/PIN 文件、备份、临时文件及别名缺席。不创建 Device，不构造虚假系统认证票。
- 已有系统保护槽：真实 `BiometricPrompt.CryptoObject` 解密 device 材料；`OpenAtomicWorkflow` 验证完整状态 AEAD。Go 只读取内部 `stateBinding`，匹配 endpoint、namespace、账号和原 generation，逐次检查原密文，然后执行成熟 Logout。无需旧设备仍获服务器信任，也不调用 View 取得信任。

PIN、混合残留、未绑定账号、不同账号/代际、未知或受损保护对象均阻断；不调用无账号匹配的 `forgetLocalPIN`。邮箱 proof 属于其他账号也不能删除当前槽。

匹配 Logout 后，Kotlin 依次执行真实 device/workflow 删除及 setup intent 完成，关闭 Go flow/device、清缓冲并释放旧 owner。`owner.clear` 已退休旧 lease，不能继续以它声称空槽；必须重新 acquire 固定槽并验证全部已跟踪对象缺席。新 owner 持有到原 Attempt 返回和最终排空。

Go 通过可信原生 `NativeAccountResetCleanup` 回调完成这些动作，并在 POST 前后重新 `CheckEmpty`。回调没有 caller cleanup/auth 布尔，禁止 Dart 实现或注入。`RequiresDeviceDeletion` 是删除意图，不能作成功凭据。清理、快照、释放不明均阻止成功交付；提交可能已接受时只能查询原事务。

## 取消与结果

系统认证复用已有真实 SDK 生命周期票；公共查询/空槽操作要求实际前台、解锁观察及有限超时。后台、锁屏、取消和 dispose 立即退休 RAM、取消请求并失效 writer，worker 随后排空。取消入口只请求退休；不能把立即返回解释成物理清理完成。

`NativeAccountResetDrain` 保证同操作只安排一次清理，先 worker Close/释放，再主线程 completion，最后允许 shutdown。清理异常仍交付失败，completion 抛错也执行最终 shutdown；executor/主线程无法接收时永久标记清理不确定。不会发布成功或把未完成清理解释为空槽。

元数据结果固定 `trustedDevice:false`。重置成功不恢复旧 vault，不登录、不初始化新 vault、不授设备权限；这些仍走原正式流程。已删本机资料无法因网络失败回滚。发生进程死亡或破坏阶段中断时，保留成熟精确删除意图，但本片不凭未认证残留自行完成另一账号清理。

## 验证边界

Go 业务测试使用合成内存 adapter、真实 AEAD 密封状态与 CAS；密码/协议原包测试保留在 `accountreset`。Android 使用真实 gobind Java ABI 和 API 36 编译，排空与既有生命周期只运行 JVM host 组件。它们均不能替代真实 Android CryptoObject、Keystore、文件删除、DAG 排空与 UI 产品流程的实际执行证据。P3 产品验收保持未完成。
