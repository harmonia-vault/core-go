# App PIN 私有 Go 包装器候选

这是未接产品的实验性 native 接口。当前 Plugin、UI、Go AAR、WorkflowProfile 和能力开关均未改；不能据主机测试宣布 Android PIN 批准 CLI 已通过。Android 独立存储 5 项 PASS 是另一批证据，其无权限包读取到的 BLOCKED 不能作为 PIN 资格。

固定原生 `PinNativeCore` 适配才可调用这些接口。pkg、namespace、slot、HTTPS endpoint 来自 native 固定配置；原生必须先用实际系统服务确认 NO_SYSTEM_AUTH、无旧系统钥/状态、未锁定升级 latch。系统取消、失败、临时 lockout、硬件暂不可用或未知状态不得走 PIN。系统后来 ready 必须先按既有 Keystore MAC 单包方案持久锁定升级；正确旧 PIN + 真正 CryptoObject 的迁移尚未实现，因此升级后普通 PIN 业务仍关闭。

## 私有 ABI

- `NewLocalPINSetup(pkg, namespace, slot, endpoint, LocalPINLifecycle)` 只生成临时新 Ed/X 设备与独立 CSPRNG gen/epoch；`ScopeJSON()` 只返回 public Binding。native 创建前先判真实资格，创建或取消失败必须关闭该临时 core。
- `Create(pinBytes, fullReentryBytes)` 接收完整 ASCII 6–32 位双录，调用公开成熟 appsecurity.CreateRecord。返回 `harmonia/native-pin-provision/v1` JSON bytes：`recordBase64` 是 Record.Encode 的原始规范密文字节，`attempts` 是初始 AttemptState。不要经 JSONObject 重排 record 后重新编码；应直接 base64 解出原 bytes。临时 Device 和 72B 材料在该调用结束清除，不返回材料或 lease。native 必须将 record+limiter 同一 MAC/AtomicFile/fsync/readback 事务发布；发布失败不能重复 Create 或声称初始化成功。
- `OpenLocalPINCore(fixedPkg, fixedNamespace, fixedSlot, fixedEndpoint, protectedScopeJSON, lifecycle)` 只接 MAC 验过的 public scope，严格匹配固定配置。Scope 本身不是账号/设备可信证据。
- `Execute(pin, completeIntent, record, sealedWorkflow, nativeCA, store)`；`ExecuteApproval` / `ExecuteEnrollment` 在 completeIntent 后另接 shortCode bytes，其余参数相同。全部参数只能在 native 包装器调用，PIN/短码可由 UI 输入，record/context/CA/store/许可不得从 Dart 注入。返回成熟业务 JSON，不返回 session、密钥、完整保护上下文或 lease。
- `LocalPINStore`：Acquire/Release、LoadAttempts→JSON、CommitAttempts(expectedRevision int64, nextJSON)、SaveWorkflowSealed(packet)。尝试 JSON 必须有 exact lowercase revision/recordHash/total/failures/delaySeconds，pendingAttempt 可省略；unknown/duplicate/missing 或 uint64 超过 Long.MAX_VALUE 拒绝，不截断、不用浮点。
- `LocalPINLifecycle.RetireOwners()` 必须同步关闭该 slot 的独立 native Workflow/Recovery owners，返回真实失败。回调不得重入当前 LocalPINCore 的 Close/Execute（当前同步调用持其互斥锁）；可关闭独立 registry/资源。Close/Cancel 先取消本次操作再等待清可控材料，不删除云端数据。

## 操作顺序与保存

规范化完整成熟 command 后，以固定域、完整 Binding、mode、原 ID/全部字段和短码计算仅 RAM 的 operation hash。重建 command 仍经成熟严格 parser 和 endpoint 检查；所有 Recovery operations 当前明确拒绝，不以 PIN 或 boolean 绕 process owner。其他方法原能力和服务器逐次授权仍由成熟 Workflow 执行。

native 实际 MAC snapshot → DecodeRecord 且原 bytes 必须等于 Record.Encode → Provider.New → whole-attempt lock 内 fresh Load/持久 precharge → Argon2id64MiB3p1/AEAD → 持久 settle → 成功 Release → 私有一次性 lease.Consume → ImportProtectedMaterial → OpenWorkflow/验证保护上下文 → 成熟 Execute/Approval/Enrollment → 关闭 Device/Workflow/lease。lease 在发放前释放 whole-attempt 锁，native adapter 还须通过固定 slot 的业务 BUSY gate 串行全操作，保护状态保存应对捕获的原文件摘要做 CAS，不能因新实例而同时覆盖另一 pending journal。

状态 AES namespace 用确定性编码+SHA256绑定 PIN 的 pkg/namespace/slot/endpoint/mode/gen/epoch/双 pub，继而调用成熟 OpenWorkflow 的用途分离 KDF/AEAD，不改其协议。new namespace 与原系统模式不同；不能直接移用系统模式文件。状态 callback 必须写入 PIN slot 的固定私密独立文件并同步原子读回，不能拿 MAC metadata 或“成功登录”替代 receipt/root/source ledger 验证。

成熟接口的 pending/unknown 原签包、原 ID、samePull、最终 native save gates 原样保留。PIN成功本身不给 cloud trust。logout/revoke 的 `requiresDeviceDeletion:true` 只通知固定 native adapter 必须删除该 slot 的 PIN packet/alias/limiter/workflow/journal、同步关闭 RAM owners；当前 core 立即关闭，不能再业务。正式 adapter 在精确清理成功前不能向 UI 报完整本地退出，失败诚实报告 PERSISTENCE，不声称 durable 成功。forget 从不解包旧设备或删除 cloud vault，重新 setup 必须新 Ed/X/gen/epoch，再走真实批准或恢复。

早 setup 错误仍返回失败、关闭临时 Device；部分错误路径保留原配置错误而不是覆盖为 RetireOwners 的错误，不能由此声称 native 清理成功。native 的 setup catch/完整 slot cleanup 尚未集成。failed-save/failed-retirement 只能证明本实例拒绝，不证明磁盘或系统资源已退役。

PIN不是 vault key。固定 Argon2/AES随机包封没有快速 PIN verifier，但低熵 PIN 的离线猜测仍可能发生；MAC/AtomicFile/noBackup 不抵抗 root 完整快照回放。Go/JVM/JNI复制、GoGC、Argon/AES内部内存不保证全部硬擦。fmt/JSON/Gob opaque 不抵抗 same-process reflection/unsafe/内存读取。平台生成软件 Ed/X 不宣称一直在硬件内。

## 本轮实测

固定 public core32b02936fe24de9e6b7d5da1100c158b7a89b3eb 归档，仅加入两 Go 候选；没有 live shared、GoMod、Plugin、Gradle 或现 AAR 改动。

- 最终定向 race：6 主 + 3 子 PASS，Go package 11.873s；真实 Argon2/AES，无 KDF mock。
- 同一最终源码 vet PASS。此前完整 mobilebridge 普通回归 PASS1.646s；其后仅补两新文件的 canonical Record/必需 attempt 字段拒绝并重跑定向 race/vet。
- 正确 PIN oneConsume 后成熟 View 仍 NOT_TRUSTED；wrongPIN/reopen 保留计数；precharge/settle/Release失败业务未触达；严格 intent/KDF/metadata/native整数；BUSY取消保留 durable charge；mature logout native-save 失败 okfalse，retire失败不伪称成功。
- Kotlin私有适配、实际有权限 classifier/Keystore+Go合体、PIN审批CLI/恢复、gomobile候选AAR构建、Plugin/UI实际产品均 UNRUN/CLOSED，待父任务复核后单独推进。
