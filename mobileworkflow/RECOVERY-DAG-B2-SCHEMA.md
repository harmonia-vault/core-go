# B2 schema 补充（父任务已批准）

intent 增加 BaseBundle 与 EnvironmentManifest；冷重载独立验证初始化签名、旧恢复身份与 head，不以 hash 语法替代证明。prepared challenge 必须与 intent 的公有基点逐字段一致。已有原 ID 重试若 refresh 发现 sequence/head 变化，只保留原记录并报 conflict，不改原 intent 或重新申请基点。

准备记录最多 2×MaxRecoveryAuthorityBytes+16384 字节；包含准备与旧 sealed 记录的整体保护状态仍最多 8 MiB。重复、未知、缺少固定字段及不应为 null 的字段均拒绝。嵌套 DAG 使用既有严格 decoder 与独立签名验证。无 bearer、恢复码、seed 或私钥进入准备记录。

prepare→sealed 在同一次 whole-state CAS 中删准备记录并存原签包。Applied 仅在原响应/查询、恢复 vault 校验及 durable CAS 后出现。受控 owner binding 只接受该原包的已验证新 Ed/X/head；原 5 分钟上限和 challenge 截止只可缩短，旧 attach target 已排空，不能复用。旧 cert4 Advance 与 CheckedDAGJournal 不放宽。

## 联合状态与原 ID 边界

- `recoveryDAGPreparation` 与现有 `recoveryDAG` 分开；前者不是已签原包。`intent` 不得混入 challenge/新钥，`prepared` 必须有完整固定 challenge 和新 Ed/X。
- 若旧 sealed 原包存在，只能是已 Applied 的 transition-v2，且 prior ID/hash/sequence 精确相同；新 BaseBundle 的恢复 head/Ed/X/generation 必须证明该旧原包的新身份。未 Applied 原包不允许新的 preparation。
- 保存 prepared 只允许沿同一 intent 前进；重复 prepared 必须完全相同。提升 sealed 时 challenge ID/nonce/expiry/session/原 ID/原基点/新公钥与签包一致，同时清 preparation；CheckedDAGJournal 仍执行原签名与单调检查。
- ordinary View/CRUD 在 preparation 或 sealed pending 时保持受限。Logout 仍通过既有保护状态流程清两者、关闭账号；旧 owner 不能复活。平台全 writer CAS/epoch 合同仍必须另行实现。

## 后续服务端 closure 合同（设计缺口，未实现）

当前 status 的 `accepted:false` 只表示查询瞬间尚未接受，不能证明已永久放弃。冷准备记录又没有完整签包；B2 不把新受限 session 偷换成原 session。

后续需要在同一账号数据库事务中以原 operation ID、原 session hash、原 challenge/basis 标识做仲裁：若已接受，返回绑定原签包 hash/sequence 的既有收据；若确认未接受，原子写入不可逆 terminal closure 并保证后续旧 challenge/签包提交不可再接受；若无法判定则维持 unknown。closure 必须能被通过完整当前码重新认证的受限客户端按原 ID 查询，不能仅依赖已丢失 bearer，且不能允许跨账号、跨原包或 ID 复用。该接口、状态、授权及迁移均需独立协议/服务端审查，本片没有新增 endpoint 或本地过期事实。
