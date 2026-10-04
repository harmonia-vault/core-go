# P1 原恢复操作 query/close 调用合同

这是封闭 Go 桥候选，不开放 SDK/MethodChannel/public capability。本片依赖已冻结 B3a+B3b 桥，不改变成熟协议或恢复域。

## 外层与完整码

继续 `ExecuteDAGRecovery(commandJSON, completeCode)`；SDK后续如接线，完整码是独立 Uint8List，不能放 JSON/日志。每次系统认证打开独立 captured AtomicWorkflow，再 attach native opaque registry。JSON唯一字段 version=1、canonical HTTPS endpoint、operation，以及下面该操作的字段；不接受 owner/session/key/target对象或权限manifest。Go始终清空 completeCode 参数。

成功外层固定 `{version:1, profile:"issuer-recovery-dag-v1", operation, ok:true, trustedDevice:false, data}`。硬错误没有成功或soft DTO，只有Go错误；native适配不得公开错误原文/秘密或据此猜阶段。这里不新增 `ORIGINAL_RETRY_REQUIRED` soft分支；网络/认证/CAS失败均保持原包。

## 四个操作

| operation | 必须字段（全部string） | completeCode | 行为 |
| --- | --- | --- | --- |
| dagRecoveryResolutionInfo | 无 | 长度0 | 成熟高层核验本机原目标/closed收据，只读metadata |
| queryDAGRecoveryResolution | operationId、targetHash | 完整当前恢复码，1–512字节 | 同原目标的新受限证明只查原操作，不生成新ID |
| closeDAGRecoveryOriginal | operationId、targetHash | 完整当前恢复码，1–512字节 | 明确 resolve-or-close；先持久原closure意图，只有成熟CAS成功才输出closed |
| openDAGRecoveryAfterClosure | 无 | 完整当前恢复码，1–512字节 | 只有已保存closed且无活动原包时，显式完整HPKE核验新owner；不自动开始新rotation |

operationId沿现有效ID语法，targetHash是64字符小写hex。桥层query/close在任何恢复HTTP前核对成熟Info的原ID/hash，不能拿调用者字段拼server目标。目标由本机sealed签包及已存challenge/账户/代际/双公钥/原sessionhash安全推导，server当前证明凭据与原sessionhash不同。

## 适用范围与不可关闭状态

只支持 `sealed transition-v2 / old-recovery`。recovered-v2登记、intent/challenged准备和无目标状态明确unsupported/原目标缺失，零resolution POST；不为这些状态提供万能关闭。Info成功目标ID和hash必须非空，失败不编造空hash。UI先用成熟B2/B3a状态判别适用阶段，不能用错误自动探测/猜阶段。

普通native Invalidate→锁外Close是RAM取消/离开，不能等于serverclosed或删除持久原包。未知/accepted:false不能重开；必须查询同原ID或保留pending。服务器关闭不表示服务器验证未保存的client权限manifest，本片不投影这类声明。

## metadata成功投影

前三操作的data固定：

```json
{"version":1,"profile":"recovery-operation-closure-v1","operationId":"original-operation","targetHash":"lowercase-hex64","observation":"pending","localState":"pending","confirmation":"none","sequence":"0","rotationRequired":true,"trustedDevice":false}
```

仅允许成熟状态组合：

- pending + unknown/pending + none + sequence0：继续保原包，不能认为关闭。Info可保守返回unknown，不替代当前服务端query。
- accepted-original-confirmed + accepted + original-history-confirmed + 正sequence：成熟原签包/完整历史确认完成，仍不是设备可信，不以closed重开。
- closed + closed + native-confirmed + 正sequence：服务器权威终态已在同一whole-state CAS保存；closed墓碑、原pin、全部已见record与下界永久保留。

所有序号十进制string，Go不转double。DTO无token/key/code/challenge/签包/manifest。openAfterClosure的data复用现DAGInfo `{recoveryGeneration,sequence:string,environments,rotationRequired, trustedDevice:false, expiresAt:string}`；完成后用户必须另行明确begin，生成新ID，不复用closed原ID。

## 取消、未知结果与认证生命周期

闭锁回应未知或最后CAS失败不能返回closed或清原包。新的认证Workflow从native保存快照重开，先Info获得原ID/hash，用完整当前码query原操作；如果服务端已经closed，成熟高层同CAS保存才返回closed。close同原ID的重复查询保原sequence，不能覆写accepted原receipt。认证错误/代际/账户/平台epoch/native快照冲突则hard失败，registry退役，迟到结果不输出。

保留既有v.mu每句柄有界排空合同，不锁住别的句柄；registry/Workflow/持久锁不跨网络，锁外Invalidate立即取消记录context，Close只排空本句柄。此片未重新定义SDK系统认证语义。
