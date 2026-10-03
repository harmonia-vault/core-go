# B3a：恢复后明确登记原包，设备仍受限

v2 只修复 B3a preparation 的嵌套 exact-schema 解码，未重跑下表 v1 完整矩阵；v2 的定向结果与原审阅 FAIL 单独记录。

本切片将 B2 已完成的 `old-recovery/continuous` 原活会话接到 cert5 手机登记：用户明确选择环境、`ro/rw/admin` 角色和期限后，先保存意图，再取得并保存同一个 challenge，最后一次 whole-state CAS 用完整双签原包替换 preparation。提交前查询原 ID，接受后验证原包并持久确认。全部 Go 结果 `TrustedDevice=false`；没有 Boot/Pull 或设备可信来源提升。

基线为 core `eef671302e4f51f75581384385e01107633423d0`、workspace `e4c304feab094e7d784a26f0aa8508e94477ff63`、server `2f15b94ce5023357320b415e5f3a4aebb29c2856`、protocol `1c0b24180e7fabfcd9109dbabb2afbf6195f22d8`。这是独立 Go 候选的验证，不追认后续平台或安装器提交已经运行。

## 入口与持久状态

| Go 入口 | 约束与结果 |
| --- | --- |
| `DAGRecoveredEnrollmentChoices` | 仅原 registry 的 `rotated` owner；刷新并返回环境版本、明确 sequence/head，没有设备能力。 |
| `SealDAGRecoveredDevice` | 传 `DAGRecoveredIntent{ExpectedSequence, RecoveryHeadHash, SelectedRights}`；生成的原 ID 先随意图 CAS，随后原 challenge CAS，再进行 HPKE、grant 和恢复/设备双签。 |
| `RetryDAGRecoveredDevice` | 同 owner、同原签包；先 GET 原 ID，未接受才尝试 POST 原包，收据与已验证 DAG 确认后 CAS。不会生成新 ID、nonce 或重签。 |
| `DAGRecoveredDeviceInfo` | 仅持久元数据。`interrupted-original` 要求原活 owner；`accepted-not-device-applied` 只表示登记原包确认，仍未完成 B3b。 |

`recoveryDAGRecoveredPreparation` 复用现有受保护状态 wrapper，绑定 endpoint、账号代次、手机 ID/双公钥、owner epoch 和整个 sealed snapshot；内部严格区分 `intent` 与 `challenged`。完整字段包括原 session hash、原 ID、原 sequence/head、恢复代次/双公钥、初始化 pin/hash、可验证的 BaseBundle、环境版本清单、全部环境/角色/期限及其 hash，以及前一个已 Applied 的原 transition ID/hash/accepted sequence。`challenged` 另保存完整原 challenge/source/bundle。

解码拒绝必填字段缺失、非法 null、未知/重复字段和尾随 JSON（既有协议明确允许的 nullable 字段保持原规则）；准备记录与整个状态各有 8 MiB 总上限。冷加载重新验证旧身份、完整签名图及前驱原包，不能仅凭 hash 格式或 ID 认定。前驱必须是同 session 的旧恢复码连续轮换，且已持久 Applied。与旧恢复、初始化、cert4、审批、管理、已关闭账号、其它 preparation 或来源状态混合均失败关闭。

单次 CAS 同时安装 sealed 原包和移除 preparation。CAS 失败立即撤销 owner/取消 context，锁外排空 callback 后只 Close 一次；失败不更新 RAM 或持久阶段。两份独立 Workflow 竞争同一个快照时，迟到 owner 不能覆盖胜者；Logout 清除 preparation，旧 owner 不能重建关闭账号。原生 provider 仍必须让普通 Save、CAS、Logout/Forget/delete 共用真实 slot 锁、完整旧 sealed bytes 与 epoch 比较；本片没有替平台完成这些接线。

## 会话、重试和冷启动

B1 registry 持有 RAM bearer，只有每次重新认证的 Workflow 临时 attach，操作结束 drain/detach；不长持 Workflow 或平台 provider。阶段限定为 `rotated → device-intent → device-sealed → device-original-applied`；`challenged` 是同次 Seal 内的持久阶段，已有 challenge 只接受原 tuple。owner 原有五分钟上限及更短服务端期限只会缩短，不能续期。

已有意图的 sequence/head 或选择变化必须冲突并保留原记录，不能随 refresh 重置基点。完整 sealed 原包以相同选择再次调用 Seal 是零 HTTP、零保存的幂等元数据返回。临时 challenge/提交传输错误仅在明确错误类别且原状态核验成功时保留活 owner；认证、wire、持久化或绑定错误仍 retire。旧 cert4 `Advance` 和 CheckedDAGJournal 单调规则未放宽。

冷 `intent/challenged` 不会自动生成新会话来补签，返回原操作中断。冷 sealed 可以沿 S2a 用完整当前恢复码建立新的受限查询会话，只查原包：接受、查询时尚未接受、仍不明分别保留语义；新会话 `RotationRequired=true`。`not-accepted-at-query` 和本地超时都不是终结授权，不能清原包或伪造 Applied。原会话丢失后的未接受事务仍需后续服务端原子 `resolve-or-close`，包括阻断迟到 challenge/POST 的 tombstone；此接口不在本片实现。

## v1 已保存的验证结果

固定 Go 1.26.4、Node 24.16.0；默认 Go 构建，不是 BoringSSL native/SDK 或真机证明。公开摘要及覆盖性源码库存见 [recovery-dag-b3a-result.json](evidence/recovery-dag-b3a-result.json)。

| 验证 | 结果与范围 |
| --- | --- |
| 新 B3a 定向 race | 147 PASS、0 FAIL；syncclient 47.448s，mobileworkflow 62.451s。覆盖必填/原包绑定、匹配 native snapshot 后的联合 schema、三阶段 CAS 故障、独立 owner 竞争、AccountClosed、callback drain/Close，以及合法 Login 的旧入口零 HTTP/零普通 Save/零 CAS。 |
| 四包 race | 723 PASS、0 FAIL；syncclient 158.414s、mobileworkflow 146.329s、mobilebridge 16.165s、registry 1.301s。包括原 S1/S2a/B1/B2/cert4/恢复 registry/savefailure 回归。 |
| `go vet` | 四包退出 0。 |
| 消费者仅编译 | 19 包构建通过、0 个测试运行；新增一个仅由测试导入的公开签名夹具辅助包。 |
| 真实 HTTPS/SQLite | 三个独立原事务场景 / 四个 test PASS events、0 FAIL，包 30.711s。使用现有正式 TS API、真实 Go HPKE/签名、fixture 验证的 TLS 和隔离 AES+锁/CAS 模型。 |

三个 HTTPS 场景：

1. 明确 Admin 授权 → 同原包 seal → 再 Seal 零 HTTP/零保存 → 原 ID 查询/提交/确认 → 原接受状态重查。确认后仍拒绝 View，原 owner 的会话期限未改变。
2. 明确 RW 授权 → 服务端已接受但响应丢失 → 原查询确认时 CAS 故障 → owner retire → 完整当前码的新受限会话查询并持久确认原包；仍要求新会话轮换、仍未可信。
3. 明确 RO 授权 → challenge 响应丢失但意图已持久 → 冷 preparation 不得重开 owner/查 sealed（零 HTTP/零保存）→ 原 owner 同 ID 重试 → 未提交原包冷查询返回查询时尚未接受，原包保持不变。

恢复登记计数分别为 `recovered-device-challenges POST=1/1/2`、`recovered-devices POST=1/1/0`；被计量的恢复路径 Boot/Pull 均为 0。计量从恢复 owner-open 开始，明确拆分 B2 前置轮换和 B3a 操作；既有夹具的注册、邮件验证、首机初始化和首值写入位于计量之前，使用其原初始化/同步路径，不能把这里的 0 扩展为完整夹具从未调用 Boot/Pull。

`https-01-source.json` 是 v1 运行时的覆盖性源码快照，共 532 份，包含 125 个 core 测试文件（例如 appsecurity 的测试）；它不是编译器实际输入追踪。公开的 297 份清单由 `go list` 的 GoFiles/CgoFiles/C/H/S 字段、workspace 测试变体及 TS/protocol 库存筛选，不收依赖包的 TestGoFiles，也不含该 appsecurity 测试；它仍是覆盖性库存，可能含未编译文件，不能声称每份都被编译。199 份 Go 清单同样按覆盖库存解释。库存字节及原 SHA 保留，不将后续 v2 修复追认为原运行源码。

早期失败原始日志保留：默认 Go cache/loopback 沙箱限制、一次错误 module cwd，以及测试夹具的恢复 seed 十六进制/十进制误用、错误字段和 journal 字段定位。签名拒绝未弱化；夹具错误修正后才记录 PASS。它们不是新的产品认证成功证据。

复跑：core `mise run test-mobile-dag-recovered-components`、`mise run test-mobile-dag-recovered`；workspace `mise run test-mobile-dag-recovered-https`。需要固定 server 依赖、只供合成测试的 loopback 权限和可写 Go cache。

## 未完成

B3b 的同一正式 Boot/Pull、可信来源提升和最终 durable save 仍未实现；新 cold owner 不能从登记原包直接获得管理能力。服务端 terminal closure、Android/iOS 的 B1/B2/B3 全生命周期接线、UI/ABI/capability 入口均不由本片开启。没有 SDK、真机、VM、CLI 配对、CI、Release、安装包或线上部署结论。

## v2 嵌套 exact-schema 修复

独立审阅确认 `selectedRights[0].role` 改为 `Role`，或同时包含同值 `role`/`Role`，会被 Go JSON 的大小写折叠接受。两个原负例和 v1 全部 PASS 原记录保留；这是字段合同缺口，没有证实签名或授权绕过。

v2 在 B3a 解码中增加 raw JSON 与 typed marshaler 规范形状的递归核对，覆盖每一层对象键、数组元素、必填存在性和 scalar/null 形状，再执行原密码学/状态校验。大小写别名、同义并存不能再由 typed 解码悄悄折叠。既有协议的规范 nullable 仍保留，intent 的可选 challenge 仍应省略；没有放宽 CheckedDAGJournal、cert4 或其它 decoder。

新负例仍放入原有测试文件，交付路径保持 24 个。固定合成向量中的 243 个嵌套对象都经过真实 decoder alias/并存探测（486 个拒绝断言）；所有对象字段共 6200 个精确名称、必填/null 形状断言，8 个规范 nullable 保留，intent/challenged 正例仍通过。这些断言不是额外累计的 Go PASS 事件。

最终布局的有限两包 race：145 PASS、0 FAIL，syncclient 72.912s、mobileworkflow 51.108s；另两包 vet 退出 0，mobilebridge/registry 两个消费者仅编译、0 tests。合并测试文件前的定向 145 PASS 原日志另存，不累加。v2 没有重跑 v1 的完整 723 项或三条 HTTPS 场景，也没有 SDK/原生/UI/VM 结果。root 的最新公开基线整合复验仍待完成。

源码库存标签已更正为覆盖性快照，可能包含未编译文件。原 532/297/199 份清单、SHA、时间和 PASS/FAIL 不变，v2 源库存单列；既有 v1 记录不作为 v2 全矩阵结论。定向复跑入口：`mise run test-mobile-dag-recovered-schema`。
