# P3 七动作重置端口

本合同基于现有邮箱证明协议，独立于 ordinary Execute 和 DAG。Go helper、Dart真实端口候选已实现；公共平台 Channel 注册、真实 SDK/邮箱 UI 与产品能力仍未验收，不得据此开放 cap。

固定 Channel：`org.harmoniavault/native/v1`。

| 方法 | 精确参数 | 返回 |
| --- | --- | --- |
| `requestAccountResetEmail` | `{endpoint:String,email:Uint8List}` | 固定 JSON `{version:1,accepted:true,trustedDevice:false}` |
| `beginAccountReset` | `{endpoint:String,proof:Uint8List}` | 原证明 Query 的 outcome JSON |
| `beginAccountResetQueryOnly` | 同上 | Query-only outcome JSON，永久不能 Prepare/Complete |
| `queryAccountReset` | 无参数（null） | 原 proof/原 RAM Attempt Query 的 outcome JSON |
| `prepareAccountReset` | `{password:Uint8List,confirmation:String}` | `{version:1,prepared:true,trustedDevice:false}` |
| `completeAccountReset` | 无参数（null） | 原 payload 完成且原生清理/空槽重取确认后的 outcome JSON |
| `cancelAccountReset` | 无参数（null） | null；本地退休和取消，不代表服务器撤销或物理清理完成 |

平台逐次精确验证 endpoint 等于其当前受控范围；包名/namespace、CA、账号/代际、owner、cleanup、固定槽路径不得通过参数提供。空参不接受空 Map 或额外字段。邮件申请创建独立 RAM mail owner；取消必须同时退休邮件 owner 与现有 reset owner，并排空自己的 worker 后交付，不等待其他账号的 owner。

Go 工厂 `OpenNativeAccountResetMail(endpoint,namespace,additionalCA)`；方法 `RequestEmail(email []byte)`、`Close()`。原工厂与六动作保持既有 NativeAccountReset 合同。邮箱 UTF-8 1–320字节，不含 NUL/CR/LF；proof 是邮件中的完整四字段 JSON UTF-8，1–4096字节；password 是完整 UTF-8 1–16384字节，确认必须用户明确输入 `DELETE_OLD_VAULT`。字节缓冲在成功、失败、取消均消费；Go/JNI/Dart运行时可能复制，不能声称消除所有副本。

接受邮件请求不确认邮箱存在或送达，不返回 accountId/proof/token，也不授设备信任。证明必须通过 Query 核验，旧 proof 的 account/generation 与本机 AEAD 固定范围由原生匹配，不能凭 Dart 声明。服务器 HTTP accepted/complete 仍不等于本机已清理。

outcome 顶层精确 `{version:1,trustedDevice:false,outcome:{state,accountId,accountGeneration,source,...}}`。Query source=status，没有 replayed；Complete source=commit 且 replayed 为 bool，或原 Query 已 complete 时 source=status。旧 generation 的 pending 或旧+1 complete，不允许别的账号/代际。未知同 RAM 原包必须先 Query；冷查询只能查询、不能拿旧 proof 新建替代包。

Dart `MethodChannelAccountResetPort` 实现七动作，`NativeAccountResetAdapter` 保留默认空 compiledActions/verifiedActions，两者求交。`compiledAccountResetActions(capabilities)` 只读取精确 bool `nativeAccountReset`（六动作）及 `nativeAccountResetEmailRequest`（邮件）；缺失或非 bool 不启用。平台尚未公共注册这些方法，不能填 true。取消 capability 也必须经过同一双门。取消开始 adapter 永久 retired，新 scope 必须创建新 adapter；取消失败或晚到成功均不能复开。

未知错误只返回固定业务分类，不使用 PlatformException message/details 或服务端任意 body；没有密码、proof、token、邮箱的日志或 toString。UI只用稳定 AccountResetActions；后台/scope变更即 retirement，清输入与显示账号，不把 UI 清理当原生物理删除许可。

本片真实 HTTPS/SQLite 验证合成 .invalid 邮件和原证明流程；本机 cleanup 为 Go 隔离 adapter，未运行 Android/iOS SDK，也未证明实际槽删除或 UI 最终闭环。
