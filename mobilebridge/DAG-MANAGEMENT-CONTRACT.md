# P4 单环境授权管理：唯一 Go 桥调用合同

本合同对应本候选的实际 `mobilebridge/workflow_dag_management.go`。最终来源以 FINAL-MANIFEST 的文件哈希为准。没有平台绑定、SDK 或 Flutter 实测；compiled 名单不是 verified evidence，默认能力继续关闭。

## 独立入口

Go 导出 `ValidateDAGManagementCommand(command string) error`、`DAGManagementProfile() (string,error)`、`(*VaultWorkflow).ExecuteDAGManagement(command string) (string,error)`。平台应在每次真实系统认证后打开同一来源的 AtomicWorkflow，沿既有 captured slot、排空、RequiresDeviceDeletion 和精确版本再验合同调用。不得转入 ordinary Execute 或用普通 restore 取得成功 view。

profile 精确对象：`{"version":1,"profile":"issuer-recovery-dag-v1","operations":["cancelDAGManagement","dagManagementDevices","dagManagementInfo","prepareDAGDeviceGrant","retryDAGManagement"]}`。本片未指定或开放平台 MethodChannel/cap；平台 owner 需按实际生成 ABI 单独编译。

command 是最多 4096 字节 UTF-8 严格 JSON，共同字段 `version:1`、规范固定 `endpoint`、`operation`。重复键、未知字段、null、未知操作拒绝。所有 ID 为 1–64 个 ASCII 字符，首位是字母或数字，后续仅字母、数字或 `._:-`；与实际 nativeDAGID 和长度门相同。没有独立秘密 bytes 入参。

| operation | 额外字段 |
| --- | --- |
| dagManagementDevices | environmentId |
| prepareDAGDeviceGrant | requestId, environmentId, subjectDeviceId, role, expiresAt |
| dagManagementInfo | 无 |
| retryDAGManagement | requestId |
| cancelDAGManagement | requestId |

`role` 精确为 `ro/rw/admin/none`；`expiresAt` 是规范十进制字符串，范围 0–253402300799。有效权限的 0 表示用户明确选择永久，当前临时 Admin 仍会拒绝永久或超过自己截止的权限。`none` 输入必须为 `"0"`；用户若选择日期必须明确拒绝，不能静默改为 0。none 只撤销一个环境，不是全设备撤销。

## 输出

成功外层固定字段 `version:1,profile,operation,ok:true,trustedDevice,data`。列表/prepare/info/cancel 的 trustedDevice 固定 false，没有授权数据 view。列表 data 精确 `{"devices":[row...],"trustedDevice":false}`；row 精确 `deviceId,role,expiresAt,keyVersion,grantGeneration`。数值均规范十进制字符串。未授环境的 row 为 role `ungranted`、expiresAt `"0"`、keyVersion 空、grantGeneration `"0"`；none、过期和旧 KV 的签授权状态保留。没有 name、platform、public key 或伪造服务器 sequence。

prepare/info/cancel data 精确 `{"management":info,"trustedDevice":false}`。info 精确十字段：`state,requestId,environmentId,subjectDeviceId,role,expiresAt,attempted,sequence,applied,canceled`。expiresAt/sequence 是字符串，其余 flags 是 bool。

| state | attempted | sequence | applied | canceled |
| --- | --- | --- | --- | --- |
| none | false | "0" | false | false |
| prepared | false | "0" | false | false |
| pending | true | "0" | false | false |
| accepted-not-applied | true | 正值 | false | false |
| applied | true | 正值 | true | false |
| canceled | false | "0" | false | true |

none 的三个 ID 和 role 全为空，expiresAt 为 `"0"`。其他状态三个 ID 非空合法，role 为上述四角色；none role 的意图 expiry 保持 0。sequence 不超过 9007199254740991。info 无参数只报告当前唯一未完成原操作；全部历史完成/取消后为 none，不可据 none 复用旧 ID。

retry 只有成熟原 receipt 确认、正式完整 P4 Pull、原来源最终 native whole-state CAS 和 postCheck 都成功，才返回 trustedDevice true，data 精确 `{"management":info,"source":source}`。info state 为 applied。source 完整复用已成熟的 nativeDAGAppliedView，包括账号/代际/设备/checkpoint 和已授权环境、变量投影；没有 key、token、签包或 journal。

只在原操作确实仍保存且属于同一 requestId 时，将 pending 或 accepted-not-applied 软化为外层 `ok:false,trustedDevice:false`，data 精确 `{"original":info,"trustedDevice":false}`，error 精确 `{"code":"ORIGINAL_RETRY_REQUIRED","retryOriginal":true}`。没有 view。对已经 Attempted 的本地 cancel，错误为空也可能是这份 ok:false 原包续办投影；必须检查 ok 和 canceled，不能将 nil 错误当取消成功。原 ID/hash/随机封套不变；只允许原 ID query/retry，不能自动新签、换 ID 或把 accepted:false 当未提交。

来源/权限/冲突、普通非 5xx HTTP、native 持久化和终态失效是硬错误，字符串结果为空。平台只能沿既有固定错误分类与 RequiresDeviceDeletion；不得从任意 body 猜可重试/已应用。

## 持久与取消边界

每次在线操作重新 Boot/P4Pull，已验安全状态先同 captured source/hash/epoch/CAS 下发保存。prepare 的实际生成器 fresh 目录和 retry 的实际重交目录，在 HPKE/POST 前先进入共享 receiver 历史；callback 深拷贝，不能改变生成器使用的控制。

已确认原 grant 的 Packet/hash/严格接受序号即使尚未 Applied，也进入同一 receiver GG/hash/sequence 下界；后到旧目录不能抹掉刚确认的 none。完整原签包和目录历史冷复验，不创建第二份裸 Highest。下界防已见回放，不是未知隐藏撤销或密码学 absence 证明。

本地 cancel 仅允许从未 Attempted 的原包，保留完整取消记录并永久退休其 ID，不是 serverclosed。Attempted unknown 和 accepted 原包不能取消。journal 最多 32 个原记录，满额拒绝且不驱逐安全历史。整体状态 8MiB、单 packet 2MiB；DAG 来源与 ordinary Management 保持分离。

全设备 revoke、manager reanchor、旧来源升级仍未接入本片；P1 产品不能仅以本桥源码或主链测试称为完整手机可管理验收。
