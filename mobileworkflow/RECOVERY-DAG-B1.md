# 恢复 DAG B1：独立 RAM owner 与认证 lease

本片实现 Go 层独立 typed RAM registry、可排空的单次 journal port 和 syncclient 的 verified binding。没有 native ABI、平台 provider 或 UI 入口，也没有新业务 challenge、Begin、Seal、Retry 或换代。实验性安全软件，不能据此宣称完整恢复或生产可用。

## 调用与生命周期

`NewDAGRecoveryRegistry(scope)` 接受受信任 Go/native 配置的 namespace、固定 slot 与平台 lifecycle epoch；scope 本身不证明认证。`Workflow.OpenDAGRecoveryOwner` 只允许没有 sealed original 的当前未可信保护状态，以完整当前码创建受限 RAM session。已有任何原包均在网络前拒绝安装，继续使用 S2a 冷查询，不能把 fresh query 当原会话。

`Workflow.RecoveryDAGOwnerInfo` 每次重新核本次 Workflow 的账户、代际、设备双公钥、SessionEpoch、完整 snapshot 和平台 scope/epoch，再临时 attach 当前 checked journal。返回的是已验证 session 的元数据，不发新 recovery-vault GET，因此不表示服务端此刻仍未撤销会话。结果始终受限、设备不可信；后续任何业务仍需独立审核实现与当次服务器鉴权。

verified binding 来自 session 内已验证 proof、pin、初始化承诺、恢复 head/公钥、sessionHash 与原包元数据，不接受外部替换；不能序列化，不返回 bearer 或私钥。registry 不暴露 session、handle、任意 Sign/Save 或自由 operation callback。既有 cert4 registry/Advance/typed assertion 未改。

每次调用只在短锁内占用唯一 lease；session 方法不持 Workflow/registry 锁。port callback 持读锁，detach 用写锁排空并清引用；闲置 owner 不保留首次 Workflow/provider。active Close/Logout、Clear/Close、取消、TTL 或存储错误立即 invalid/cancel，外层释放业务锁并 drain 后 exactly-once Close。保存/清理失败不得被成功结果遮盖。

owner 创建时固定最多五分钟的 monotonic deadline，服务 expires 只能收紧，重复 attach 不续期，墙钟回退拒绝。正常 idle `Workflow.Close` 不清 owner，才能在下次独立认证后继续。**idle 后台/Logout/Forget 必须由未来持有 registry 的 native 宿主显式调用 Clear/Close；本片未接这些 SDK 事件。** 即使宿主尚未 Clear，新 Workflow 的 snapshot/AccountClosed/epoch 检查也会拒绝旧 owner。测试不宣称该平台事件链已完成。

## 固定源码与验证

基线：core `dc28eb87c5cc49051210dece33e17cb83c8fe9e0`、workspace `92853660b2ed787e4cb2e257b91f7b2fd29a0c15`、server `d27fb2a98b86d2b657869830f00c1e8d07402aed`、protocol `3168864b5228913e4286ba8d2fcca9f3f3574b6b`。Go 1.26.4、Node 24.16.0、tsx 4.20.6，darwin/arm64 默认 build，无 BoringSSL tag。

- `mise run test-mobile-dag-owner`：四包 race **466 PASS 事件、0 FAIL**，其中 B1 新增 **40 PASS 事件**；包含受影响 S2a、旧 cert4、registry 回归。主测试与 subtest 各算一事件。
- `mise run test-mobile-dag-owner-https`：**一个真实 HTTPS 场景 PASS**，2.595 秒。既有 Go→隔离 TLS→TypeScript→临时 SQLite 合成环境；native 存储为合成 AES/同槽 CAS provider，不是 OS 认证。
- 同四包 vet 成功；core 全部 18 包消费者编译成功（13 个测试包、5 个无测试文件包），**0 个测试实际执行**。

HTTPS 场景先用现有 helper 建合成账户/初始化，独立手机 actor 登录，再明确模拟 native 的 Export+seal。B1 仅发 discovery、恢复认证 challenge、恢复 session、vault GET 各一次；第一个 Workflow detach 后关闭，第二个独立解包 Workflow 读取同 RAM session Info 成功。第二 Workflow 没有 HTTP，请求阶段 CAS commit=0，完整保护 bytes 不变。未证明两次真实系统认证，也未创建新的恢复业务事务。

组件覆盖 scope/账户/代际/设备/snapshot/pin/session/head 替换、已关闭 Workflow、sealed original 不能提升、Busy/S2a 互斥、active Logout/Close、TTL/墙钟回退、半 session 网络失败、detach 屏障、Save 失败立即撤销和 exactly-once Close。源与结果摘要见 [脱敏证据](evidence/recovery-dag-b1-result.json)。

## 原失败与范围限制

首次组件编译因测试夹具引用不存在的 `w.save` 失败，改为既有 `persist`；此前 syncclient 的局部 PASS 不替代最终重跑。第一次 HTTPS 在准备阶段失败：Login 只更新内存，夹具没有执行 native 通常负责的 Export+seal，因而 slot 尚不存在。仅补测试准备后同场景通过，生产逻辑没有因此改动。39 组件 PASS 与 465 四包 PASS 的中间运行均保留；新增网络 Open 清理负例后最终固定源码完整重跑 466 PASS。原始历史不重标为最终源码。

B2 prepare 持久记录、完整新码重输、prepare→sealed 原子迁移、同原会话重投与换代仍只是设计。服务端没有旧未接受事务的权威 closure，不能写本地 expired/abandoned 或伪造 Applied。未实现 cert5 应用、明确环境/角色/期限登记、Boot/Pull 后可信或 P4 管理。

真实平台仍需让普通 SaveSealed、DAG CAS、Logout、Forget/delete 的所有 writer 在同槽锁下比较认证时捕获的完整旧密文、SessionEpoch 与平台 lifecycle epoch，并排空旧无条件 writer。Android owner 的 typed opener/provider 是独立切片，本片不改 bridge 文件；iOS 实际 CAS/provider、gomobile 回调、硬件因素、系统认证及 SDK 生命周期均未验。不启 UI/native cap，不运行 VM、CI、Release 或部署。

完整码输入 byte slice 返回时清零；Go 字符串和 GC 副本不能承诺物理擦除。公开内容只含源码、任务、本文与脱敏 JSON；原始日志、个人路径、合成钥/CA、数据库和二进制留私有。mise 合并须保留其他 owner 的新增任务。
