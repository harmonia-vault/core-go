# 设备配对内核

该包使用固定版本 BoringSSL SPAKE2 的公共 API，并通过标准 HKDF-SHA256/HMAC-SHA256 确认绑定账号、用途、挑战、角色和两端设备公钥。当前 macOS arm64 原型已通过真实原生测试，Android arm64 静态库构建和 Go 测试二进制链接已通过；Android 运行、完整手机批准与设备入网流程仍未完成，不能宣称生产可用。

详细字段、调用顺序、版本与测试范围见统一开发目录中的 `protocol/docs/PAIRING.md`。默认构建关闭原生配对，返回 `ErrUnavailable`。

```sh
cd pairing
mise run test
mise run native-build
mise run test-native
mise run test-vector-node
mise run test-default-cross
```

本机构建产物与上游副本仅存于 Git 忽略的 `native/`、`.cache/`，不上传二进制。工具链固定在本目录 `mise.toml`；原语固定版本在 `boringssl.lock.json`。`testdata/pairing-application-v1.json` 与协议仓库向量一致，只覆盖应用层编码与密钥确认，不是 SPAKE2 标准向量。

Harmonia 源码采用 MIT 许可证。

## Android arm64 编译

显式传入已安装的 NDK 28.2.13676358；构建入口不会安装 SDK/NDK。可选第二个参数指向已经核验的固定 BoringSSL 源码；省略时从官方仓库取得固定提交。

```sh
mise run native-build-android /path/to/ndk/28.2.13676358
mise run test-android-compile /path/to/ndk/28.2.13676358
```

产物为忽略目录中的 `native/android-arm64/libcrypto.a` 和 `.cache/pairing-android-arm64.test`。固定参数为 `arm64-v8a`、API 21、PIC 和 `c++_static`；只构建静态库，不执行交叉编译的上游测试。Go 检查使用 `GOOS=android GOARCH=arm64 CGO_ENABLED=1`、`harmonia_boringssl` 标签以及 NDK Clang 的 `--target=aarch64-linux-android21`。Go 的 Android 目标同时满足 `linux` 构建约束，因此现有原生实现会被选中；候选 `android,arm64` 链接参数已通过真实完整链接。

本轮实际结果：NDK r28c/Clang 19.0.1 构建通过，四个 SPAKE2 公共入口均使用 `HARMONIA_BSSL_` 前缀；静态库对象为 ELF64/AArch64，Go 测试文件完整链接为 ELF64/AArch64 动态类型。未在 Android 执行该文件，不能把这些结果称为 Android 配对运行通过。Flutter 桥接和设备负向测试仍待验收。参考 [NDK CMake 官方说明](https://developer.android.com/ndk/guides/cmake)、[NDK Clang 官方交叉编译说明](https://developer.android.com/ndk/guides/other_build_systems) 和 [Go 构建约束](https://pkg.go.dev/cmd/go#hdr-Build_constraints)。

## Windows ARM64 原生配对

Windows ARM64 固定 BoringSSL 库与项目配对包已取得真实运行结果；默认配对仍关闭，正式 CLI/专用系统服务链尚未验收。构建入口、固定 SHA、实际通过/失败记录和后续验收门槛见 [Windows 原生配对说明](WINDOWS_NATIVE.md)。
