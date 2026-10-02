# Android Go 原生业务桥切片

这是实验性安全软件。该切片已通过 Go、真实 Android JNI 密码学和系统设备密码包封测试；不代表 Flutter 的登录、首次可信手机、远程批准、同步或恢复流程已接通，也不代表生产安全验收。

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

## 2026-10-03 本机证据

- Go 普通与原生标签 `go test -race ./mobilebridge` 均通过，4 项顶层测试。
- 固定 gomobile AAR 实际构建通过；Java API 和 arm64 `libgojni.so` 已核对，未只交付 stub。
- Android Kotlin、debug 应用和 AndroidX runner 合成测试 APK 实际编译通过。compileSdk36，运行的是 Android14/API34、arm64 的隔离 AVD；不能把编译 SDK 当运行版本。
- 原生业务测试实际 4/4 通过（终轮 0.046 秒）：Go JNI 真密码学、独立/未可信设备钥、导入/关闭、严格字段/端点、未入网拒绝，以及系统锁屏未配置与已配置两种情况下的认证门槛。
- 系统设备密码全流程 1/1 通过（57.474 秒）：三次独立认证分别完成生成包封、解包执行 Go 加密检查、重新取得与初次生成严格相同的双公钥。保存的是 108 字节 AES-GCM 包，不含明文材料头；前次认证不能复用到新 cipher。
- 系统取消流程 1/1 通过（17.052 秒）：精确 `AUTH_CANCELLED`、无设备文件。
- 本机 KeyInfo 对每次认证返回 duration0、type3、256bits；旧 API 文档约定的 -1 和本机 0 都表示没有时间授权窗口，其它策略拒绝。
- 最终诊断日志已删除。测试自己的 alias/文件在 finally 删除；合成 AVD PIN、认证 dump 与两个新 fixture 包已清理，原预览包、其它 AVD 数据与模拟器会话保留。构建/测试原始证据仅保存在手机仓库忽略的 `build/native`。

强生物成功路径、真机硬件保护、Android 远程配对/首台手机/共享同步/恢复、iOS 仍未完成。Flutter 默认 `FailClosedGateway` 和 `realVaultReady=false` 保持，不将该切片的能力标识作为安全操作放行条件。高层工作流应独立保存版本化的 endpoint/account/generation/public-keys/checkpoint 上下文，并用另一份绑定 AAD 的原生 AES 状态文件封装；不能塞进当前 72 字节设备钥格式。

依据：[Go 官方 gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile)、[Android Keystore](https://developer.android.com/privacy-and-security/keystore)、[认证参数](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,%20int))、[KeyInfo](https://developer.android.com/reference/android/security/keystore/KeyInfo#getUserAuthenticationValidityDurationSeconds())。
