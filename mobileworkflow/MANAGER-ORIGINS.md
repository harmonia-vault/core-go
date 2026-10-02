# 非初始管理手机与环境来源

本 Go 切片供原生系统强认证后的持钥层使用。没有新增 Flutter UI、Dart 命令或 Android 入口；不代表生产可用。非初始管理手机无需 `Root == self`，也不能从服务器设备目录或任意根自签授权自动建立信任。

## 真实入网与应用门槛

登录只建立短时随机登录会话。`EnrollDevice(ctx, EnrollmentInput)` 在本次调用内运行真实本机 SPAKE2，验证 PAKE 双向确认、精确账号/代际/设备双公钥、cert3 双签及 HPKE 封套，取得完整不可变原 receipt。短码和 PAKE 私有状态不持久化。完整 receipt、原随机登录 bearer、截止时间和 epoch 先经原生 AES 保存，才提交 Complete。

`EnrollmentInfo` 只有 `state=complete` 且 `trustedDevice=true` 表示本手机已应用。服务器接受序号和已固定根可先保存，但仍 `accepted-not-applied`；普通 View、缓存、CRUD、审批全部关闭。唯 `ResumeEnrollment(ctx, originalID)` 可用原 receipt 查询/完成，再经同一 origin 验签 Pull 接收缓存及账本，重验账本、检查 checkpoint 不低于接受序号，并最后原子 AES 保存 `applied=true`。缓存保存或最终保存失败时该标记回退，重启也不能泄出缓存。登录 session 到期擦 bearer，不隐式替换 ID/PAKE/角色；Logout 仍可清除。

受保护字段 `enrollmentV3,omitempty` 保存精确 receipt、原会话及已接受/已应用状态。未确认 receipt 不能含根或云缓存；已应用字段必须有原双签 receipt、相同 root pin、足够 checkpoint 和已验证非空 ledger。`AccountClosed` 上下文不能靠此记录复活；CompleteEnrollmentAtEpoch 仅在已知服务器接受原 receipt 后使用。

## 永久来源锚与动态来源图

根手机只用原生保存的精确 `InitialAuthorities`；非初始手机只用本机已 PAKE 确认的 cert3 receipt 得到 root Ed/X 和同一原初始化 grant 哈希集合。verifier 为 `NewRootPinnedVerifierWithOrigins` 或 `NewPinnedVerifierV3`。New 和离线 View 重新验证受保护 `Cloud.IssuerEvidence`；cert3 缓存缺 ledger、跨 endpoint/账号/代际/设备、公钥替换或额外 genesis 都拒绝。候选当前服务器图仅证明已固定初始来源之后的历史控制链，不产生新的根或当前 Admin。

批准采用独立 `ApprovePairingV3/RetryApprovalV3/ApprovalInfoV3/CancelApprovalV3`，既有 v2 原生接口不改。每个角色/期限由用户明确选择，短码本次内存使用。当前在线权限再次核验后，经 `PrepareEnrollmentProofV3` 取得 proof、本机 pin 和精确 initial，交成熟 `SignEnrollmentApprovalV3` 预签验证；保存原包及 choices hash 成功才 HTTP。原 ID 查询/重试不改 nonce、proof、角色或签名。未知审批保留业务门槛；当前失权或父授权变化阻止重投。

## 环境两包事务

新建和轮换使用 `/environment-changes-v2`：数据签包、控制 origin 签包、完整 content hash、已验证当前控制图/原权限和旋转前 recipient 集共同进入原生加密日志。原 v1 create/rotate 请求不会在未知结果时偷偷升级或重新加密；缺原 origin 明确 `ErrLegacyEnvironmentOrigin`。

新建环境的本机 Admin 期限不超过所据现有 Admin。轮换在线验证完整当前有效 device recipient 集，独立生成新环境钥，保持各 recipient 原角色/原期限（包括比执行者期限更晚的只读设备及永久管理员），增加 key/grant 版本，生成全部 device 和当前 recovery HPKE 封套，把全部当前 shared 值重加密签名后一次提交。不根据离线缓存猜 recipient；control 序号与本机验证 checkpoint 不同时拒绝竞争。

保存原请求先于 POST；结果不明查原 ID 和两包 content hash。接受以后必须相同 Pull 验证环境事件头序号、原内容 hash 与所有重加密 mutation 的连续批次；原接收回执保存整事务尾序号，不把后续幂等 retry 当新写。旧恢复根过渡链尚未接入时，不从服务器图自动改 recovery recipient。

## 实际证据与边界

工作区 `acceptance/mobile_manager_test.go` 使用合成 `.invalid` 账号、捕获邮件替身、随机测试钥、临时 SQLite、验证证书的 127.0.0.1 HTTPS 和真实固定 BoringSSL SPAKE2。AES 保存替身只代表 Go 原生边界，不算 Android PIN/Keystore 新 API 验收。

`mise exec -- go test -race -tags harmonia_boringssl ./acceptance -run 'TestMobileManager|TestMobileGeneric' -count=1 -v`：2 主项、6 场景 PASS，包执行 14.416 秒。

`mise exec -- go test -race -tags harmonia_boringssl ./mobileworkflow ./syncclient -count=1`：两包全部 PASS，分别 3.894 秒 / 3.550 秒。来源缺失负例现在于 New 重验账本时提前拒绝，仍检查审批 POST 为零。工作区源码基础扫描 PASS。

- 入网完整回执保存失败时 Complete POST 为零；服务器接受回执保存失败、同 Pull 缓存/ledger 保存失败、最终 Applied 保存失败、已接受响应丢失均不开放 View/CRUD，也不报告 trusted。原密封回执重启查询/恢复后才应用。
- A 批准 B 限时 Admin X；B 原生密封重启后创建 Y；B 批准 C 仅 Y RO，C 解密 Y、不能写 Y；B 轮换 X 保留 A 永久 Admin、B 原期限及 D 更晚截止的 RO，并保留当前 X 值，A/D 接收新钥正确。
- 创建与轮换接受后丢响应，原生重启用原 ID/两签包查询；HTTP 创建/轮换总共各一次，未发生新写。旋转回执尾序号精确匹配原批次。
- 已应用 cert3 缓存删除 issuer ledger 后 New 明确拒绝。

完整恢复码的数据恢复目前仍是独立受限切片；带有效 origin 的多环境恢复下一批接入。丢失全部设备后恢复为新管理设备，需恢复公钥连续过渡与显式新授权，尚未完成。不得用 recovery completed 布尔提升设备可信；不得把恢复签名私钥持久化到磁盘。
