# Android Go 原生业务桥切片

这是实验性安全软件。该切片已通过 Go、真实 Android JNI 密码学和系统设备密码包封测试；原生高层首根管理手机另有下述逐操作切片；不代表 Flutter 完整流程、远程批准或恢复已接通，也不代表生产安全验收。

## 边界与接口

`Device` 在 Go 使用独立随机 Ed25519/X25519 软件钥匙。只有原生平台可导出/导入 `HARMKEY1 + Ed25519 seed32 + X25519 private32`；这 72 字节只供 Android AES-GCM 包封，不经过 Dart 或 MethodChannel。原生每次系统认证后临时导入，操作完 `Close` 清理。Go/JNI/Android 可能复制内存，不能承诺擦除所有运行时副本。

版本 1 的 JSON 命令严格限制大小、UTF-8、唯一字段、操作枚举和每操作字段。端点只接受无凭据/查询/片段的 HTTPS 地址，拒绝非规范端口、编码路径、路径跳转等。`ExecutePublic` 只提供能力、端点检查与新合成资料的密码学自检；认证后的 `Device.Execute` 只提供未可信公钥与持钥密码学检查。未入网设备的读取、写入、批准、撤销和恢复继续拒绝，不允许界面传入角色作为权威。

`NativeSelfTest` 实际调用 Go SHA256、Ed25519、标准库 HPKE、XChaCha20Poly1305 与固定 BoringSSL SPAKE2，并检查上下文替换、签名/密文篡改、未确认通道钥与确认重放。未链接原生 SPAKE2 时自检失败。该本机两端自检只使用新合成资料，不能被当作远程配对批准。

Android 原生层使用 `BIOMETRIC_STRONG | DEVICE_CREDENTIAL` 和 `setUserAuthenticationParameters(0, ...)`，每次 AES 使用均绑定 `BiometricPrompt.CryptoObject`。不支持、失败或取消均拒绝；没有弱生物、普通明文 AES、Passkey 或要求人脸的替代路径。软件 Ed/X 私钥不始终在硬件内，Android Keystore 的保护/认证强度也没有真机硬件证明。AES 密文只在应用 `noBackupFilesDir` 原子保存，目录 0700、文件 0600；AAD 绑定应用、文件 slot 和版本。AAD 属于受保护操作，必须在成功认证后提交。

## 可复现构建

固定 Go1.26.4、x/mobile `v0.0.0-20260908204917-8b95e45f8d3e`、Java17、NDK28.2.13676358；BoringSSL 固定提交 `fab96f87245d7c6b941515201843665122650b88`。官方 gomobile 生成 arm64 AAR，最低 Android API30。工具依赖单独保存于 `mobilebridge/binding/go.mod`，不向核心主模块添加 x/mobile 依赖。

```sh
# 在 workspace 的 mobile 目录，SDK/Java/CMake 由固定 mise 工具解析。
mise run go-native-build
mise run android-debug

# 在 core-go 目录，普通构建必须拒绝未链接的原生自检。
mise exec go@1.26.4 -- go test -race ./mobilebridge -count=1
mise exec go@1.26.4 -- go test -race -tags harmonia_boringssl ./mobilebridge -count=1
```

`mobile/tool/native-build.sh` 若缺 BoringSSL Android 静态库会调用固定 `pairing` 构建任务，然后调用 `mobilebridge/build-android.sh`。NDK 缺失时给出明确错误，不隐式下载或接受许可证。独立脚本也可显式传入 SDK、NDK 与 Java17 路径。AAR 位于手机仓库忽略的 `build/native/harmonia-go.aar`，Go 工具缓存位于核心仓库忽略的 `.build/mobilebridge`。不公开二进制、私钥或签名钥。直接 Gradle 构建缺少 AAR 时明确要求先运行 mise 任务。

## 2026-10-02（UTC）本机证据

- Go 普通与原生标签 `go test -race ./mobilebridge` 均通过，4 项顶层测试。
- 固定 gomobile AAR 实际构建通过；Java API 和 arm64 `libgojni.so` 已核对，未只交付 stub。
- Android Kotlin、debug 应用和 AndroidX runner 合成测试 APK 实际编译通过。compileSdk36，运行的是 Android14/API34、arm64 的隔离 AVD；不能把编译 SDK 当运行版本。
- 原生业务测试实际 4/4 通过（终轮 0.046 秒）：Go JNI 真密码学、独立/未可信设备钥、导入/关闭、严格字段/端点、未入网拒绝，以及系统锁屏未配置与已配置两种情况下的认证门槛。
- 系统设备密码全流程 1/1 通过（57.474 秒）：三次独立认证分别完成生成包封、解包执行 Go 加密检查、重新取得与初次生成严格相同的双公钥。保存的是 108 字节 AES-GCM 包，不含明文材料头；前次认证不能复用到新 cipher。
- 系统取消流程 1/1 通过（17.052 秒）：精确 `AUTH_CANCELLED`、无设备文件。
- 本机 KeyInfo 对每次认证返回 duration0、type3、256bits；旧 API 文档约定的 -1 和本机 0 都表示没有时间授权窗口，其它策略拒绝。
- 最终诊断日志已删除。测试自己的 alias/文件在 finally 删除；合成 AVD PIN、认证 dump 与两个新 fixture 包已清理，原预览包、其它 AVD 数据与模拟器会话保留。构建/测试原始证据仅保存在手机仓库忽略的 `build/native`。

上述为首轮原生钥匙切片历史证据。强生物实际成功、真机硬件保护、远程配对批准、恢复和 iOS 尚未完成；首根管理手机的 Go/Android 独立业务入口见下节。Flutter 默认 `FailClosedGateway` 和整体 `realVaultReady=false` 保持，不将某一操作的能力标识作为全部安全操作放行条件。

依据：[Go 官方 gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile)、[Android Keystore](https://developer.android.com/privacy-and-security/keystore)、[认证参数](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,%20int))、[KeyInfo](https://developer.android.com/reference/android/security/keystore/KeyInfo#getUserAuthenticationValidityDurationSeconds())。

## 首根管理手机原生高层（2026-10-02 UTC）

`workflow.go` 的 `Device.OpenWorkflow` / `VaultWorkflow.Execute` 只由本次系统强认证成功的 Kotlin 层调用。`WorkflowProfile` 逐操作声明 `first-root-admin-v1`，整体 `realVaultReady` 仍为 false。注册、邮件证明验证、连续登录与首次初始化、完整恢复码重输确认、原 proposal 查询、验签读取、环境及变量 CRUD、首根 Admin 自撤销与 pending 元数据查询、退出具有独立入口；批准/恢复/轮换/角色/重置均拒绝。Dart adapter 只传表单意图与稳定操作 id，未替换 Flutter 默认 gateway、未修改 UI。

业务全部复用 `mobileworkflow` / `syncclient` / `cryptox`。密码只在 Go 派生登录凭据，经标准 HTTPS 发送；原生系统信任根通过证书 PEM 加到 Go RootCAs，合成测试 CA 仅由原生测试构造器显式追加。没有 `InsecureSkipVerify`、自定义放行 hostname、HTTP 或携带凭据/查询的端点。端点每命令严格校验，并与持久文件固定绑定，服务器重定向不传会话。

每次认证解包 72 字节独立设备材料后，Go 用标准 HKDF-SHA256、独立 `harmonia/native-workflow-aes/v1` 用途域，从高熵设备材料派生本次软件 AES256-GCM 状态保护钥。用途域固定应用包、文件 slot、版本、完整 endpoint 和精确双公钥；状态 AAD 再绑定账号/代际、deviceId、双公钥、checkpoint 与关闭标记。它不是密码派生钥，不改变云环境的独立随机钥，也不声称此软件 AES 钥始终硬件内或每次状态保存重新硬件认证。

状态使用独立 `HARMST01` 版本、最长 8 MiB 明文的可变长 AES 包；设备的 `HARMKEY1` 72 字节格式不变。JNI 的 `SealedStateStore.SaveSealed` 只收到密文，Kotlin `ProtectedWorkflowStore` 在 noBackup 私有目录同步 fd.sync、0600 权限及 AtomicFile 提交后读取核对，成功才允许 Go 后续 POST。内层状态、短时 pending token、私钥/凭据均不返回 Kotlin/Dart。原生保存失败、取消、处置期间的保存或边界替换均拒绝；失败不自动产生新 id。若 AtomicFile 已提交后核对失败，不保证恢复旧版，后续只能从已认证的持久状态恢复原事务或关闭。密文文件的 AAD 与内层完整 schema 双重检查；不声称能检测有完整应用私有文件恢复能力的任意旧文件回滚。

每个调用串行、BUSY 拒绝并发；本次业务结束 Close 清软件状态钥和 Go 设备材料。dispose 取消原生认证与 Go context，停止后续保存；已经到达服务器而响应丢失的操作只能通过原 id 处理。退出与已证实设备失效要求同时删除对应 Keystore alias、设备文件和状态文件，失败不报告完整成功；不能靠登录自动恢复旧本机信任。

实际 Android14/API34 arm64 证据：完整 Go→合法 TLS→TS/临时 SQLite 原生纵链 1/1（73.957 秒），随后补 BUSY/取消的纵链 2/2（83.512 秒）；初始化和变量接受后 502，密封状态重新 New 后保持原 proposal/签包/id 恢复；重复 id 的 checkpoint 不增加，不同意图同 id 拒绝；保存失败原文件不变且服务端 mutation 计数不增加；离线已验缓存、环境/变量 CRUD、退出删除钥和文件后拒绝访问均实际通过。未信任合成 CA 时注册拒绝 1/1（11.022 秒），捕获邮件计数未增加。测试只在独立 nativefixture 包，合成 PIN/账号/值，不覆盖预览应用。最终全套证据见下段。

复现合成 HTTPS 夹具（不用于生产服务，不保存 CA 私钥）：

```sh
# core-go目录；--workspace 是上级主仓库；输出必须放 ignored build。
mise exec -- go run ./mobilebridge/cmd/androidfixture --workspace .. --output ../mobile/build/native/workflow-fixture
# mobile目录，固定构建后以独立测试包安装。既有合成AVD需设备凭据。
mise run go-native-build
ANDROID_USER_HOME=/tmp/harmonia-android-user mise exec -- ./android/gradlew -p android -PharmoniaNativeFixture=true assembleDebug assembleDebugAndroidTest
```

AndroidX `NativeWorkflowIntegrationTest` 的 `syntheticCA` runner 参数为夹具生成公开 ca.pem 的 Base64；私钥只活在夹具进程。只允许合成 AVD 的测试 PIN 交互；测试源码日志仅含操作阶段，不输出秘密或账号/值。`NativeWorkflowStorageTest` 独立验证中断写与超限拒绝保护旧密文，其合成 packet 不被当作 Go 可解密上下文。

最终同一 AAR/Android APK 的实机运行环境为隔离 arm64 AVD Android14/API34（compileSdk36），12/12 通过，184.013 秒，共 40 次系统设备密码提示交互（包含取消）：原生基础 4、钥匙包封/三次独立解包与一致公钥及取消 2、AtomicFile 中断/超限/0600 1、高层 5。高层五项为完整注册初始化/密封原 id 恢复/CRUD/BUSY/退出、取消不联网/不改保护资料、未知 CA 链拒绝注册、正常 200 自撤销和接受响应丢失后的未知自撤销。两个自撤销分支都实际删除对应 Keystore alias、72B 材料文件与独立状态文件，随后钥匙不可用；`completed=true` 只用于已验证 200 回执及 sequence，status401→boot403 时明确 `completed=false / acceptanceUnknown=true / deviceInvalidated=true`，不虚报自己的接受结果。pending 时 View/Pull/CRUD 拒绝缓存，只有认证后的 info 返回原 id/expiry。

自撤销短时原随机 bearer 和原签包只在密封 pending journal，原 id/status 查询在前；到期 scrub 原 bearer 后只允许 fresh boot 查询原 id，不重 POST、不生成新 id、不打开旧缓存。`REVOCATION_EXPIRED_PENDING` 仍表示自己的接受结果未知；可以显式 Logout 清本机资料。真机与强生物成功路径未测试，APK也未发布。

最终 Go 普通/native-tag race 通过（1.446/1.393 秒），Flutter业务静态分析无问题（5.8 秒），固定 AAR 与 Kotlin main/test APK 构建通过。清合成 PIN 后再跑未配置凭据门槛 4/4（0.028 秒）。所有测试 alias/文件在 finally 删除，两个 nativefixture 包已卸载，原 preview 包仍存在；同 AVD 数据未 wipe/reset，模拟器继续运行，loopback HTTPS/临时 SQLite 夹具已停止。最终原始记录为 mobile ignored `build/native/workflow-full-runtime.txt`、`workflow-final-no-credential.txt`、`workflow-native-build-final.log` 与 `workflow-android-build-final.log`。

完整仪器测试 runner 类为 `NativeBridgeIntegrationTest,NativeCredentialIntegrationTest,NativeWorkflowStorageTest,NativeWorkflowIntegrationTest`（同 `org.harmoniavault.harmonia_mobile.nativebridge` 前缀），测试包 `org.harmoniavault.harmonia_mobile.nativefixture.test/androidx.test.runner.AndroidJUnitRunner`。需在显式隔离 AVD 建立临时合成 PIN，通过系统提示，取消测试点主动取消；结束后清 PIN/测试包。禁止将此步骤用于真实用户手机、真实锁屏或账号。

## 首根手机批准 compiled CLI 的原生 v2 切片

2026-10-02 UTC，独立 executeApproval 短码字节入口与 retryApproval/approvalInfo/cancelApproval 已接通。系统强认证后使用本机来源重建签包，两次真实密封完成才POST，unknown只查原id，approved与双签complete分开。正常AAR focused跨端1/1(59.074秒)与可复现入口1/1(58.733秒)通过，各21提示含1取消；known/accepted502、两保存失败门槛及compiledCLI持钥boot/Pull/隔离导出/rw写入均实际验证。上述通过使用当时默认v2的c4dec971编译基线；新CLI默认3后当前controller明确certificate-version2。origin-aware复测55.248/54.702秒失败后，服务器补历史mutation授权及写入者双签身份来源闭包；新正常AAR/当前CLI（1801392+dirty）仅一次fresh focused1/1 PASS59.634秒、21提示含1取消/四controller0，known/accepted502、两保存前置失败和同id确认均实际通过。以记录的实际产物哈希为界，不将后续Go改动算作该运行证据。详见 [APPROVAL_NATIVE.md](APPROVAL_NATIVE.md)。整体false；新Genesis恢复、cert3/非根/新环境来源和UI未算此证据。
