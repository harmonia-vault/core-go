# 受限恢复与完整新码轮换

本切片由 Go 原生持钥业务调用成熟 `cryptox` 原语及既有 HTTPS `LifecycleService` 协议。兼容入口 `BeginRecovery` 保持已冻结的初始环境、根设备直签历史范围。新的显式入口 `BeginRecoveryWithOrigins` 通过精确原初始化双签和完整 origin 图验证新增环境、跨密钥版本和非根历史来源；缺任何必要来源或封套签包时拒绝。此切片尚未接入 Android 恢复操作，也不完成丢失全部设备后的新管理设备授权。所有结果的 `trustedDevice` 始终为 false，不是生产可用声明。

## 调用合同

一次系统强认证后创建 `Workflow`，在同一原生操作内先 `Login(email,password)`，再 `BeginRecovery(完整旧码)`。登录只解析邮箱对应的账号及代际；恢复信任由输入完整码派生的当前恢复公钥独立验证。固定 SHA256 登录凭据、密码、恢复种子及恢复码都不持久保存，随机登录 token 也不会被当作恢复 token 使用。

`BeginRecovery` 精确检查一次挑战的账号、代际、用途、nonce、恢复代际、短时截止和完整签名数组。恢复签名取得 15 分钟受限会话后，从 `recovery-vault` 获取根、当前恢复封套与签名历史。只用本地完整码派生的公钥验证当前根，再请求显式 `?capability=issuer-origin-v1` 的 `originalInitialization`。原 proposal 的设备 ID、Ed/X 双公钥必须精确等于已验证的当前根；成熟 `InitializationProposal.Hash` 校验原恢复根签名、所有原初始 grant 签名及封套字段，原设备签名和原恢复签名再验证同一用途限定 proof。只有这份原双签 proposal 中的初始 grant hash 能成为初始来源；服务器标记的 sequence=1 不是密码学证明，当前根自签授权也不能扩展初始环境集合。原恢复公钥由原设备初始化签名绑定，允许当前恢复码轮换后的公钥不同。验证来源后 HPKE 解开环境钥，校验写授权、设备签名、账号/环境/密钥/授权版本和接受序号，最后 AEAD 解密值。原初始化 proof/签名在刷新及恢复轮换前后必须保持不变。缺失原两签、增加环境、跨密钥版本及未证明 issuer 仍拒绝。候选 `issuerEvidence` 仅作为未信任 JSON 保存以兼容服务器，限定 1 MiB、对象或 null、有效 JSON 和无重复字段；兼容入口不以候选图扩大初始集合，新的显式 origins 入口会按下述合同独立验证。服务器未签名的 `publicDevices` 目录不作为信任来源。

`RecoveryInfo()` 返回纯元数据，`RecoveryView()` 返回明确标记受限的已验证变量视图。普通 View/Pull、变量或环境 CRUD、审批、自撤销全部拒绝。恢复缓存独立于普通 `Root`/`Cloud`，不会通过布尔值把设备变为可信。当前响应缺少已签环境名称来源，因此受限视图只有环境 ID、密钥版本和值。

`BeginRecoveryRotation(id)` 先刷新持久快照，生成独立新随机种子，派生新恢复签名/接收钥，保留精确根设备双公钥并重签恢复根，为所有当前环境生成新恢复封套。完整原 proposal 先经原生 AES 原子保存，再申请一次轮换挑战；新完整码仅在这次返回供用户离线保存。若返回 `ErrRecoveryPending` 且 code 非空，原生层仍须向用户保留这次完整码和原操作 ID。随机种子不会为了重试而保存，也不生成替代码。

`CompleteRecoveryRotation(完整新码)` 每次从用户完整重输重新派生新钥，与已密封 proposal 的两公钥逐字核对。先查询原 ID；未接受则使用原 proposal/nonce/session 和确定的原签名，不换 ID，不换会话重签。新签名绑定 account、account generation、原 session hash、recovery generation、一次 nonce、完整新公钥、全部封套 hash 和新根 hash。原生保存原签名成功前不 POST。

服务器完整原子替换恢复公钥、根及全部必要环境封套后，客户端还必须用同一恢复会话重新获取 vault，验证新根、完成序号、完整封套集与原 proposal 一致，从重输新码 HPKE 解开全部新封套，核对环境钥不变，重新验签和 AEAD 解密。最后原生密封也成功才返回 `rotation-complete-restricted` 和 `rotationRequired=false`。只收到接受回执或最后密封失败时返回 `ErrAcceptedNotApplied`，缓存继续关闭，原 ID 可重启继续确认。

`QueryRecoveryRotation()` 只返回受保护原操作的元数据。服务器已接受但尚未重输新码并完成封套/值验证时返回 `accepted-unverified`，仍然 `rotationRequired=true`。它不能代替完整重输或把管理权限偷偷打开。轮换完成也不自动注册设备；后续显式恢复新管理设备的可信根历史过渡和授权入口仍需实现。

## 密封状态与失败处理

本恢复状态使用 `recovery,omitempty`，与审批和自撤销日志分离。原生 AES 状态包含受限会话及截止、原 session hash、已验证恢复根和快照、环境钥、原 proposal/挑战/签名/接受序号；不含密码、固定派生凭据、恢复种子/完整码或设备私钥。完整 endpoint、账号/代际、当前原生设备双公钥、原生认证边界及检查点继续由 `New` 固定验证。全状态最多 8 MiB。

恢复期间的 token、环境钥和缓存只能传给原生认证后的 AES 密封回调，不能给 Dart、日志或明文文件。每操作 New/Close，Close 清 Workflow 的进程材料并关闭 HTTP 空闲连接；独立 process-only RecoverySession 仅解除引用，其生存期由原生 registry 管理。软件钥和运行时副本不能保证始终硬件内或绝对擦除。

看到挑战到期会永久关闭原 nonce 的本地提交窗口；看到会话到期会擦 bearer 并密封，保留仅用于未知结果辨识的原 ID/hash/签名。持久化已见时钟，回拨不能重新开放已关闭窗口。会话到期后没有权限确认原操作的状态，结果继续未知，不隐式生成新操作。

接收到恢复会话 401 或 stale 403 后立即擦受限缓存/token、持久化 `AccountClosed` 并清进程钥，返回 `ErrTrustInvalidated`。原生层必须删除 device/state/alias；不能只显示错误再复用旧材料。失效本身也不证明本地原请求已接受。Logout 无论是否待决都允许完整清理。其它恢复会话在原子轮换后失效；原轮换会话可继续验证已接受原操作和新 vault，仍不是可信设备。

## 实际测试证据

- Go 业务完整 race：mobileworkflow 1.966 秒、syncclient 2.385 秒通过；恢复单测 race 1.524 秒通过。
- 恢复安全单测 3 主项、24 个篡改子项通过（包含原双签 proposal/proof/账号/代际/nonce/session hash/原恢复公钥/根设备篡改）；覆盖账号/代际、原 token hash、根签名、环境钥、密文、历史授权版本、未证明 issuer、事件回放、伪可信根、关闭状态和仅布尔完成拒绝，以及普通/审批 API gate、退出清除、过期 bearer/回拨。
- 实际 Go→127.0.0.1 HTTPS→TS/临时 SQLite 恢复 race 5 主项、17 子项通过，18.626 秒：真实旧码 HPKE/AEAD；部分新码/旧码拒绝；接受响应丢失后重启原 ID 查询；申请挑战响应丢失恢复原 proposal；接受前丢响应重启原签包/原 token 字节一致；原生保存失败完成 POST 为零；客户端到期/回拨不重放；遗漏必要封套 HTTP 409 且旧状态/序号不变；新增环境缺 origin 拒绝；旧其它恢复会话 401 后清缓存；已接受但最后密封失败不伪报完成；原签 journal 到期去 bearer 后严格重建且不再 POST。
- 新增来源安全回归从全新原生上下文开始：真实根设备后来新建环境、轮换密钥都在缺完整 origin 时拒绝；缺原双签、替换 nonce/恢复签名、重算 proposal hash、把真实根签的新环境 grant 与 HPKE 封套伪装为 seq=1 并追加到原 proposal，都不能复用旧初始化双签获得恢复权。新码 gen=2 可在原初始化 gen=1 证据下真实恢复，证明没有错误强等旧/当前恢复公钥。
- 已冻结初始化 1 项、自撤销 5 子项与恢复初版 8 子项合并 race 通过，13.630 秒。这里的 AES 原生持久层是 Go 测试替身；不能据此声称 Android 恢复/PIN 流程已验证。

测试仅使用新注册 .invalid 账号、随机合成钥、捕获发信替身、临时 SQLite、loopback HTTPS 和隔离 AES 数据，不读取宿主环境或用户真实凭据，不发送外部邮件。客户端时钟测试未更改真实 Node 服务器时钟。


## 完整来源入口与封套真实性

原生下一接入必须显式调用 `BeginRecoveryWithOrigins(ctx, 完整旧码)`，失败不能退回兼容 `BeginRecovery`。成功密封 `originsRequired=true`，重启 `New` 在任何视图前重新验证完整候选图；删除图或以兼容布尔状态替代不能打开缓存。当前码验证当前恢复根，原设备初始化签名认证原 proposal 的旧恢复公钥，原恢复签名认证同一初始化 proof；只有原 proposal 中的精确初始 grant hash 能成为图的起点。`issuerEvidence` 从这些承诺核验所有身份双签路径、origin 双父来源和本快照实际写授权；只核当前环境/密钥版本所需历史，已删除环境的无关旧 raw history 不成为数据来源。服务器 `publicDevices`、图中历史 targets、过期或已撤销设备都不自动赋予恢复手机任何当前权限。全部旧设备已撤销时仍可验证合法历史数据。

所有恢复 vault 请求显式增加 `envelopeEvidence=recovery-envelope-v1`，服务器与 vault/原初始化/来源图在同一受限事务快照返回完整已接受的公开签包。HPKE 只有收件公钥就能封装任意钥，不足以证明发送者或环境钥来源；空环境必须同样核验恢复密文：

1. 初始恢复代际：逐字匹配原双签 proposal 对该环境、KV=1 的 recoveryEnvelope。
2. 当前 KV 的新增/轮换：核完整 SignedEnvironmentChange 的签名、数据 hash 和完整 SignedEnvironmentOrigin；管理源与全部 Before/After 来源必须已在精确 genesis 图中认证，再匹配当前恢复代际和当前封套字节。
3. 新恢复代际：完整原轮换 proposal 必须包含新根和全部封套清单；用用户输入码已固定的当前恢复签名公钥验证原 13 域 RecoveryRotationProof、完整 envelopesHash 和 trustRootHash，再逐环境精确匹配。当前新码公钥不从服务器目录 TOFU 获取。只有该公开包的签名历史用途，不从其元数据推断新的可信设备或本地操作已完成。

缺必要包、旧 rootless 12 域内部夹具、替换原签包后自行重算 hash、只给可解密密文都拒绝。合法空环境照常可恢复；不要求环境里人为增加一个用于验钥的变量。完整新码重输、显式原 ID 轮换、未知结果查询和最后原生保存门槛均保持原合同。

## 仅进程内恢复会话

`BeginRecoveryWithOriginsSession` 在同一次已强认证操作内返回独立 `RecoverySession` 和安全元数据。该资源仅保留派生的旧 Ed 签名私钥，接收私钥在 Begin 结束后清除；不能 JSON/Text 序列化、格式化输出私钥，也没有任意签名或原始私钥导出 API。私钥不进入 AES、文件、Dart 或日志。其生命周期最多 5 分钟并受原受限服务会话截止限制，同时使用单调时钟和已见墙钟，回拨不能延长期限。

每次新系统 CryptoObject 认证并解密原生上下文后，原生层可 `AttachRecoverySession`。绑定精确 endpoint、原生设备双公钥、账号/代际、恢复代际、根设备双公钥、恢复双公钥、原初始化 proposal hash 和原 session hash。轮换开始后只允许 none→原 ID/签名 proof hash，期限缩短至原挑战截止，不能改 ID/hash 或延长窗口。`Workflow.Close` 只解除引用；独立原生 registry 负责退出、取消、到期和进程结束清理。Workflow 已附加的 session 在 Logout/失效时清除；旧码派生 Ed 在原完成签名成功密封后即清除，不为重试保留私钥。

进程被杀或资源过期属于中断：`ResumeRecoverySession` 必须重新完整输入旧码，但只恢复仍存活的原受限 token/session hash/轮换 ID/nonce，不偷偷 Login 换会话或产生新操作。正常新码重输流程无需第三个旧码表单。资源当前只实现生命周期、严格绑定和清理；连续旧恢复权签名链及 cert4 新设备授权仍是下一切片，不能凭持有资源或 `RotationCompleted` 假装 trusted。

## 本批真实测试与边界

- 公开来源基线之后，最初实际空环境公开 HPKE 伪封套回归失败（1.647 秒）：客户端曾仅靠解封成功而接受错误环境钥。该失败保留作为发现记录；补完整签包后同一反例通过（1.26 秒）。
- 新完整 origin HTTPS/TS/临时 SQLite 原生 race：4 主项、8 个场景通过，15.096 秒。覆盖 A→B 临时 Admin、B 新建 Y、B 批准 C 写 Y、B 轮换 X，全部 A/B/C 撤销后从全新上下文恢复 X KV2/Y，完整新码 gen2 原子轮换、重启，以及候选图缺失/签名/伪 genesis/根/目标范围篡改与进程 session 原绑定恢复。
- 原 `acceptance/mobile_recovery_test.go` 17 场景逐字不变，本批与新增 8 场景合并 9 主项、25 场景 race 通过，37.833 秒。
- 独立实际 HTTPS 封套证据 12 子项通过，5.403 秒：缺包、缺 full change、改密文字节/重算 changeHash、伪 origin 签名、改历史授权/接受 head、重复包，当前 gen2 缺完整轮换及改密文并重算完整 envelopeHash/当前公钥/根。合法空环境、全新码恢复及密封重启也通过。第一轮测试把无恢复上下文的既有 `none` 枚举误写为 `absent`，拒绝本身正确；纠正断言后完整通过，没有放宽业务门槛。
- 合成空初始环境与新码完整清单 unit race 2 主项/9 场景通过，1.408 秒。进程 owner 生命周期 race 4 主项/5 个截止与绑定篡改子项此前通过，1.702 秒。
- 本批完整 native race：mobileworkflow 4.577 秒、syncclient 6.066 秒通过；源码扫描通过，仍需人工限定公开范围。
- Android 恢复/强认证 session 及 cert4 恢复后的新管理设备尚未接入或跑实际验收；仅 Go 原生 AES 测试替身和真实 loopback HTTPS 通过。恢复始终 restricted/trustedDevice=false，M2 整体仍未完成。

## 纯时钟回退的永久关闭修复

额外只读审查发现：此前单独回退墙钟超过已见容差、但未到会话截止时，只暂时返回 ErrRecoveryExpired；时钟回正后可重新读取恢复明文。新独立 unit 先实测失败（0.471 秒，clock 回正后 err=nil）。修复将纯回退与实际会话到期都不可逆置 SessionClosed，清随机 bearer、所有恢复环境钥和值事件缓存，关闭附加的进程恢复签名 owner，并通过原生 AES 回调持久化；clock 回正不重新授权。

已关闭记录只保留公开签名来源及原提案/nonce/签名日志，用于诚实辨识未确定的原操作。New 重新核原根/原初始化/来源/封套承诺和 journal，但必须没有环境钥/值事件，不再要求被清的解密钥，也不能开放明文或提交 HTTP。失去 bearer 后不能声称已查询服务器接受结果；原操作元数据仍可见，结果可能保持未知。原生保存失败会返回错误且当前进程仍关闭；原生接入必须沿失效清理边界关闭资源，不能把保存失败当作已经持久成功。

实测：恢复安全定向 native race 2.149 秒通过；真实 HTTPS/TS/临时 SQLite 3 主项/9 场景 race 13.416 秒通过，含新的纯回退无待决/原已签未知两项，以及原七项未知响应、保存门槛和到期 journal 回归。完整 mobileworkflow/syncclient native race 4.769/6.389 秒通过。原 17 场景测试文件未修改；Android 恢复尚未开放。
