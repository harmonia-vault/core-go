# DAG 编译投影与冷启动闭锁发现

本接口用于恢复向导的必要本机接线，仍是实验性实现。编译名单不代表 SDK 验收、服务器能力、账号权限或设备可信；默认验收证据为空，能力继续关闭。普通工作流的 `WorkflowProfile` 与 `Execute` 不包含这些 DAG 操作。

## 独立编译投影

Go 函数为 `mobilebridge.DAGWorkflowProfile() (string, error)`，零参数，返回 JSON 字符串：

```json
{
  "version": 1,
  "profile": "issuer-recovery-dag-v1",
  "experimental": true,
  "realVaultReady": false,
  "systemAuthenticationPerOperation": true,
  "dispatch": "executeDAGRecovery",
  "operations": [
    "applyDAGRecoveredDevice",
    "beginDAGRecoveryTransition",
    "closeDAGRecoveryOriginal",
    "dagRecoveredDeviceInfo",
    "dagRecoveredEnrollmentChoices",
    "dagRecoveryOwnerInfo",
    "dagRecoveryPendingInfo",
    "dagRecoveryPreparationInfo",
    "dagRecoveryResolutionDiscovery",
    "dagRecoveryResolutionInfo",
    "openDAGRecoveryAfterClosure",
    "openDAGRecoveryOwner",
    "pullDAGRecoveredDevice",
    "queryDAGRecoveryOriginal",
    "queryDAGRecoveryResolution",
    "restoreDAGRecoveredDevice",
    "retryDAGRecoveredDevice",
    "retryDAGRecoveryTransition",
    "sealDAGRecoveredDevice",
    "sealDAGRecoveryTransition"
  ]
}
```

平台接线约定为独立、无参数的 MethodChannel `dagWorkflowProfile`，返回上述 Go JSON 字符串。该约定仍需平台实际绑定、构建和 SDK 验收；Go 测试不能证明平台 getter 已存在。

`cancelDAGRecoveryOwner` 是平台处理的限定 RAM owner 取消，不在 Go 域编译名单中。平台仅在相应处理器真实编译时声明 `capabilities.nativeDAGOwnerCancellation: true`；缺少字段按 `false`。取消不代表服务器闭锁。

Dart 对 DAG 使用独立编译名单，再与经过验收的 DAG 操作证据取交集。取消能力也须经过这一证据门槛。不得使用普通工作流名单充当 DAG 名单，也不得因 getter 返回名单就打开按钮。

## 冷启动发现请求

通过现有 `executeDAGRecovery` 发送严格命令：

```json
{"version":1,"endpoint":"https://synthetic.example","operation":"dagRecoveryResolutionDiscovery"}
```

`completeCode` 必须为空。命令不接受调用者指定的操作 ID、目标 hash、owner、账号或代际。端点仍与本机受保护工作流的固定端点一致；原生认证、作用域、捕获版本及迟到结果检查沿用现有入口。

本操作只读受保护本机状态，不发网络请求、不写 CAS、不创建恢复 owner。它复用完整原包、恢复历史、closed 墓碑和已见检查点校验；校验失败是硬错误，不能变成 `none`。

成功外层格式：

```json
{
  "version": 1,
  "profile": "issuer-recovery-dag-v1",
  "operation": "dagRecoveryResolutionDiscovery",
  "trustedDevice": false,
  "ok": true,
  "data": {
    "version": 1,
    "profile": "recovery-operation-closure-v1",
    "state": "closed",
    "operationId": "original-operation-id",
    "targetHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "trustedDevice": false
  }
}
```

`data` 恰好六个字段。外层 profile 与闭锁数据 profile 不同，必须各自精确核对；hash 是原目标 `targetHash`，不能替代原签包 `contentHash`。

| state | operationId / targetHash | 含义 |
| --- | --- | --- |
| `none` | 两者为空字符串 | 已核验本机不存在本接口支持的原操作或闭锁记录。 |
| `supported-original` | 原 ID / 64 位小写十六进制目标 hash | 存在已验证的 sealed `transition-v2`，授权类型为 `old-recovery`。 |
| `closed` | 原 ID / 原目标 hash | 没有新的活动准备或原包，且存在已验证、持久保存的 closed 收据；完整历史下界仍保留。 |
| `unsupported` | 两者为空字符串 | 当前本机存在其它来源、业务或不支持的恢复阶段，包括 recovered 登记、intent/challenged 准备。 |

活动准备优先于旧 closed 记录，不能把历史闭锁投影成新事务已关闭。该接口不宣称 RAM owner 不存在，也不证明服务器当前授权或设备可信。

Dart 先消费成功 discovery；仅 `supported-original` / `closed` 才可调用成熟 `dagRecoveryResolutionInfo`，并要求 ID 与 hash 一致。`none` / `unsupported` 不触发按错误猜阶段的探测。已持久 closed 的冷启动可由此进入显式新操作路径；仍需完整当前码、新受限会话及既有高层闭锁门槛，不能本地取消后直接重开。

## 已验证范围

只使用合成数据：Go 编译名单与严格 DTO、未知字段及非空码拒绝、原 sealed 来源与冷 closed 发现、账号代际错配、受保护状态被外部改变后的硬失败、零网络和零 CAS。现有真实 HTTPS 闭锁主链增加了持久 closed 后关闭 registry、重新创建 registry 并发现同一原 ID/hash 的断言，发现步骤没有新增 HTTP。

定向 race 结果已通过；两次测试夹具错误的失败日志保留。未运行本片 Kotlin、Flutter、SDK、模拟器或 VM；未开放 capability。可信恢复后的数据仍只能由成熟 Boot、P4 Pull、完整来源校验和最终 CAS 路径给出。
