# 手机连续恢复与显式新设备

这是实验性 Go 高层业务，不是 Android 系统强认证验收。原生桥与界面尚未打开此能力。兼容 `BeginRecovery`、`BeginRecoveryWithOrigins` 和旧 13 域轮换入口保留原实验边界；本流程只走 `issuer-recovery-v1`，失败不会回落旧协议。原 17 项恢复基线验收文件未修改。

## 可调用合同

这些方法仅供通过系统认证并验证 AES 保护上下文的原生持钥层调用，不能把 `Config`、完整保护状态、bearer 或 owner 交给 Dart。

| 操作 | 行为 |
| --- | --- |
| `BeginRecoveryAuthoritySession(ctx,完整旧码)` | 验原初始化双签、全部连续链、当前码认证的固定根身份、完整封套承诺和实际 HPKE/AEAD，返回受限信息与进程 owner。 |
| `ResumeRecoveryAuthoritySession(ctx,完整当前码)` | 只恢复同一受限 token/session/hash/checkpoint；已密封签名的旧代际请求不能复活 old owner。 |
| `AttachRecoverySession(owner)` | 新系统认证操作解密原生状态后，核对端点、设备双公钥、账号/代际、本地 epoch、原初始化 hash、链尾和原 session，再附着仍存活的 owner。 |
| `BeginRecoveryAuthorityTransition(ctx,id)` | 请求并核原 challenge、完整环境版本；生成随机新码/独立新钥和全部恢复封套。只保存未签提案，原生保存成功才返回完整新码。 |
| `CompleteRecoveryAuthorityTransition(ctx,完整新码)` | 派生并核原提案新公钥，旧/新 Ed 签同一 25 域包。签包保存成功后立即关闭 old owner，再 POST；接受后验证完整新 vault、实际解封和最终保存，返回新代际 owner，仍不可信设备。 |
| `QueryRecoveryAuthorityTransition(ctx)` | 只查原 ID/原精确内容 hash/接受序号，不绕过完整新码重输和实际解封。 |
| `RegisterRecoveredDevice(ctx,id,selections)` | 用户明确选择环境、RO/RW/Admin、永久 `0` 或到期时间；实际设备 HPKE 解封后才自签 cert4。原包保存后关闭当前恢复 owner，再提交。 |
| `RetryRecoveredDevice(ctx,id)` | 同 ID、同 nonce、同两签包/内容 hash、同受限 token 查询或幂等提交；接受后正式 Boot/Pull/来源账本与最终原生保存才可信。 |
| `RecoveredDeviceInfo()` | 只返回 ID、状态、接受序号和可信门槛，不导出凭据或明文缓存。 |

`RecoveryDeviceSelection` 含 `EnvironmentID`、`Role`、十进制 `ExpiresAt`。无自动全选、自动 Admin 或自动登记。恢复轮换成功始终 `TrustedDevice=false`，只有显式设备登记最终落盘成功才为 `true`。

## 来源与封套

完整旧码认证当前 TrustRoot 的恢复公钥；原初始化的设备/恢复双签固定原根 Ed/X 与精确原始 grants。逐个 accepted transition 验前 head、旧/新独立公钥、完整环境 manifest/所有恢复封套/newRoot 和接受序号。当前服务公钥、目录和服务器序号都不能补缺失历史签名，也不能把旧 v1 new-only 断链升级为连续授权。

先验证每个封套的签名承诺，再 HPKE。原始代际封套须精确等于原双签初始化；后建/轮换环境须完整管理设备签包、origin 和精确历史权限；新恢复代际须完整连续 transition 的旧/新两签承诺。包括空环境也不能仅凭“可解封”接受。当前环境写入来源和数据 AEAD 仍逐项核验；不把历史图的 targets 当当前设备 Admin。

## 进程钥与持久化

恢复种子、完整码、恢复 Ed/X 私钥、密码及 SHA256 登录凭据不写 AES journal。`RecoverySession` 只持派生 Ed 私钥，禁止 marshal、raw-key 或任意签名；首次解封结束清 receiving private。owner 最长五分钟且受限 session 最长十五分钟，单调时钟与墙钟回退都不可逆关闭。绑定含固定设备双公钥、账号/代际、epoch、原初始化 proposal hash、链尾、原 session hash；原 nonce/transition ID/hash 和期限只能收紧。

正常每次 `Workflow.Close` 只从此操作 detach，owner 由原生 registry 独立管理。包完成密封后立即 `owner.Close`，即使网络尚未发出。原生取消、注销、失效、dispose、保存失败须永久退役 registry owner；缺 owner 不能只解密旧缓存恢复 View。进程被杀或 owner 过期属于中断，需要完整有效码重输恢复同一受限上下文；正常 old-code → new-code 流程无第三次旧码输入。原生 namespace/slot/instance 隔离和每次 CryptoObject 的证明仍由桥层实现，本轮 Go 验收不替代系统认证。

AES journal 只含随机受限 bearer、业务缓存、完整签包和公开证明。保存失败不 POST、不报告 durable；已签包未知结果先查原 ID，不能改变角色、期限、ID、nonce、token 或重封密文。原 challenge 到期禁止重投；状态未知不能假报“完成”或“从未接受”。新的环境/钥版本并发变化需显式中断重启，不能悄悄制造新 key。

## 接受与应用门槛

HTTP 200 或 status 中的 accepted 只证明服务器接受。新恢复 vault 必须包含原精确两签 transition、原完整封套、新码公钥与实际原数据钥；最终原生保存失败仍 `accepted-unverified`。

cert4 同样先保存完整两签包，再核原精确 receipt；接受记录包含原 pin、原初始化、连续链和不可变包。随后用正式 `NewRecoveredDevicePinnedVerifier` 经独立设备签名 Boot、普通 `issuer-recovery-v1` Pull 验 proof3、HPKE/AEAD、授权/数据序号和受保护账本。最终原生保存成功前 Root/普通缓存门槛保持关闭。失败回退内存 engine/cache，重启只能原 ID 查询和再应用；`Applied` 布尔不能替代回执或账本。

## 实际证据

全为合成 `.invalid` 账号、本地经测试 CA 验证的 HTTPS、临时 SQLite、真实 Go Ed/X/HPKE/AEAD；AES callback 模拟原生存储边界，不是假称 Android PIN。

- 初次草稿入口 HTTP 400（成熟 endpoint/body 映射漏项）与自授 grant 缺幂等 ID 的失败均已修正，未放宽协议。
- 真实受限 → 完整新码 → 同包两签 → 全部封套解封 → restricted/new-owner → 每操作重新 New/Attach：race PASS，3.001 秒。
- 显式 E Admin/永久 → cert4 实际 HPKE 后双签 → 正式 Boot/Pull → 新上下文再 Boot/共享 put：race PASS，4.645 秒。
- 八场景原包/保存失败，加原 challenge 过期/伪 Applied：race PASS，19.197 秒。覆盖轮换和登记的 prePOST 零提交、accepted 502 同 ID 重启、接受记录/最终保存失败和缺 proof3 时不露普通缓存。
- 全部旧 A/B/C 撤销后，恢复非根 Y 与 X KV2 的真实旧值，显式 E X 临时 RO/Y 永久 Admin；重新 Boot、RO 拒写、Y 实际共享写：race PASS，13.415 秒。
- 正式编译 CLI4：E 真实 PAKE 批准 F 仅选定环境 RO/RW，504 原 receipt 恢复、CGO0 daemon 新 Boot/HPKE、RO 拒写与 RW put/delete：另一 owned 验收普通 PASS，8.787 秒，native race PASS，10.11 秒。
- 冻结前统一连续恢复联合验收：`go test -race -tags harmonia_boringssl ./acceptance -run '^TestMobileRecoveryAuthority' -count=1 -v`，5 主测试 / 12 场景全部 PASS，35.039 秒。
- 完整 `mobileworkflow` 与 `syncclient` native race：PASS，4.709 / 8.990 秒；两包 `go vet`、owned diff 检查与源码基础扫描通过。

以上不是生产可用承诺。完整 Android process registry/CryptoObject/AES 与界面恢复流程尚未验收。E 现有变量读写可走正式 proof3 下发；环境新增/轮换、既有设备角色/撤销和再恢复控制平面当前仍使用 proof2，遇 recovered actor 明确失败关闭。平坦来源 union/profile 与这些必要产品闭环后续单独实现，不能临时 cast proof3、移动 Root 或增加全局 Managers。
