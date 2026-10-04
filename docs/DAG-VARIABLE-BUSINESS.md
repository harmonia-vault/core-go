# 已恢复 DAG 设备的变量业务桥

这是实验性首片。P1 仍要求环境 CRUD 和每环境 RO/RW/Admin、期限与撤销管理；本片不把仅读取或变量写删计作 P1 完成。Android/JNI、Flutter 产品未跑，默认逐项 verified 集合仍空。

只有 B3b 正式 Boot/P4 Pull/native 整份 CAS 已保存的 RecoveredDAGDevice 来源可用。原初始化 pin、确认登记 ID/hash、账号代际与设备双钥必须一致；目录、公钥回显、accepted 或本地布尔都不能授信任。普通 Execute、普通 WriteJournal 和管理门不开放，也不把旧 journal 自动提升为 P4。

新增 `dagWrites` 是现有成熟 Writer 业务密文日志的独立保护封装，绑定原登记 ID/hash；不属于恢复 checkedjournal，不含钥、token 或原始输入值。新 Workflow 复验原登记与全 DAG、closed-history、当前缓存来源及原日志签名/账号/epoch。原 ID 查状态、精确 hash/seq 和同一验证 Pull 才能应用；不会按当前同名值猜接受或离线写入。

独立网络 candidate 不持原 Workflow 锁。同一 Client/context 的私有回调在成熟验签和 Engine 原子接受之后先保存权威下发，覆盖首次 Pull、Writer 内部 Pull、显式授权刷新及迟到暂停投影；prepare拒写也不能留下旧权限。回调按原 hash/epoch、当前 native Check做整份CAS，失败硬停止且不继续业务POST。日志另作成熟原签包保存；每次 journal 保存仍先成熟 P4 Pull核完整当前签授权，不能把普通旧授权与新缓存拼接。最终 trusted View只在成熟 Writer精确确认、完整当前下发、最终 native CAS及postcheck都成功后出现。Close/Logout/Invalidate取消当次 ctx并拒迟到结果；保存回应未知保原材料，禁止假报 trusted。

## 严格接口

固定独立 Android Channel 名建议由实际平台候选实现：`executeDAGBusiness` 参数精确 `{command:String,value:Uint8List}`，`dagBusinessProfile` 参数 null。Go实际 API：

- `ValidateDAGBusinessCommand(command) error`
- `DAGBusinessProfile() (string,error)`
- `VaultWorkflow.ExecuteDAGBusiness(command,value) (string,error)`

command 最大4096 UTF8 bytes，精确 version=1、canonical HTTPS endpoint、operation 与下表字段，拒未知字段/重复字段/null/大小写变体/额外 JSON。requestId/environmentId沿成熟64字节ASCII ID规则。name最大128ASCII bytes、标准变量名、大小写不敏感保留 `__HARMONIA_` 前缀拒绝。put的value可以空、最多65536bytes、合法UTF8且无NUL；其它操作必须0bytes。value只RAM独立缓冲，桥finally消费调用者字节，不声明能擦除Go/JNI所有运行时副本。

| operation | 附加字符串字段 |
| --- | --- |
| putDAGVariable | requestId, environmentId, name |
| deleteDAGVariable | requestId, environmentId, name |
| pendingDAGWrites | 无 |
| retryDAGWrite | requestId |

Profile返回精确 `{version:1,profile:"issuer-recovery-dag-v1",operations:["deleteDAGVariable","pendingDAGWrites","putDAGVariable","retryDAGWrite"]}`。仅实际编译存在性；平台独立 `nativeDAGBusiness` bool与Dart显式 verified操作集合求交，默认关闭。不得并入ordinary profile或恢复20操作profile。

## 返回

所有公开JSON envelope共有 `version:1,profile:"issuer-recovery-dag-v1",operation,ok:bool,trustedDevice:bool,data`。硬错误无JSON/data；RequiresDeviceDeletion只沿明确终态失权，或已验安全变化在精确原native基点无法保存的专用错误；桥必须先只读核原捕获槽，平台仍需在同owner文件锁/快照lease内再次核原expected后清理。native槽已推进或无法证明原基点时只退休旧handle，不能要求删新scope。普通CAS失败使当前handle永久saveFailed、取消并排空关联owner，不把一般保存失败推断为撤销，也不新增caller cleanup声明。

成功写删/重试：ok/trustedDevice均true，data为 `{write,source}`。write精确 `{requestId,total:1,accepted:1,applied:true,sequences:[decimalstring]}`。source复用成熟 DAGApplied投影：原恢复登记 version/profile/operationId/contentHash/acceptedSequence/trustedDevice，binding精确 accountId/accountGeneration/deviceId/checkpoint，以及view精确 deviceId/checkpoint/experimental/environments。environment仍只有id/name/role/variables；显示已授权值，不含签包、封套、钥或token。

pending成功：ok=true、trustedDevice=false，data精确 `{pending:[row...],trustedDevice:false}`；row为 `{requestId,operation:"put"|"delete",environmentId,total:1,accepted:0|1,applied:false,canceled:bool,sequences:[decimalstring]}`。序列固定每原item一槽：本片total=1且accepted=0时唯一格式是 `["0"]`；accepted=1时为单个非零canonical十进制字符串。0只表示本机尚未确认原收据，不能据此推断服务器未接受；不接受空数组或双格式。上限32项。无变量名、值、密文或签名；canceled墓碑不恢复提交资格。

允许保原 ID 的未知：ok=false/trustedDevice=false，error精确 `{code:"ORIGINAL_RETRY_REQUIRED",retryOriginal:true}`；data精确 `{original:row,trustedDevice:false}`。只有成熟业务保留并复验该原日志后才能投影；失权、CAS失败、账号关闭、取消、原scope错配均不能按错误body猜成可继续。重试仅原requestId，不重新输入值/重签/新ID。

## 取消和已收到的安全状态

取消前已经完整验签且被Engine接受的response，才允许以原owner当前Cloud为previous进行本机授权安全投影。`WithoutCancel`仅用于成熟本机VerifyAuthorizationRefresh，不发网络/挑战/续期。投影不推进数据序号，不应用新值/标签/增权；整份候选从原owner当前状态重建，保留原日志。普通取消且无降权/删除/到期变化不保存、不标设备删除；已验安全变化不能持久时，沿上面的精确捕获槽门失败关闭。任何CAS已成功后不能用取消回滚该已保存版本。

## 验证边界

Go合成 DTO/来源门测试、真实HTTPS TypeScript/SQLite/HPKE加密业务与 AES CAS适配器测试分别记录。后者不是系统CryptoObject、KeyStore/JNI或实际Flutter产品证据。正式平台仍需实际generated Java/API编译与有界产品步骤，不能由getter或fixture入口声明生产可用。
