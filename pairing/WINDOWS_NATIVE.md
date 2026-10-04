# Windows ARM64 原生配对构建

这是实验性构建入口。固定 BoringSSL 原语与 Go 薄包装器已在 Windows ARM64 运行通过；完整 CLI 入网、当前用户 IPC、专用系统服务与开机同步仍需联合验收，不能宣称生产可用。

## 固定输入与支持范围

- BoringSSL 提交：`fab96f87245d7c6b941515201843665122650b88`。
- 配对协议：`boringssl-spake2-edwards25519-draft02-v1`；没有更换原语，不声称 RFC9382 互操作。
- 符号前缀：`HARMONIA_BSSL`。
- 官方 LLVM-mingw：`20260922`、LLVM `23.1.2`、UCRT、Linux ARM64 主机，Windows ARM64 目标。
- 工具链归档 SHA256：`07d21263c56bfe9a713db6fdb3f7434bf4c121a005e40397d3b4c0170fb06769`。
- 固定 Go `1.26.4`；调用环境须已有 Python3.12+、CMake3.22+、Ninja 和 GNU tar，不自动安装工具。本包 mise 配置固定通用 Go/CMake/Ninja 版本。

只有显式 `harmonia_boringssl` 标签、CGo 和 `windows/arm64` 同时存在才选用 Windows 原生实现。默认无 CGo、无标签及其它 Windows 架构返回 `ErrUnavailable`；macOS、Linux 与现有 Android/iOS 条件保持兼容。

## 构建目录与容器内存

先确认临时目录所在文件系统。Linux 的 `/tmp` 可能是 tmpfs，其文件也占用容器内存；`GOMEMLIMIT` 只约束 Go 运行时管理的内存，无法回收仍保留的工具链文件。两个 Windows 构建入口均遵循标准 `TMPDIR`。在既有磁盘文件系统内创建本任务独占目录，并仅对本次命令设置 `TMPDIR`、`GOTMPDIR` 和 `GOCACHE`；无需改内存、交换或容器安全设置。

```sh
harmonia_build_root=$(mktemp -d /var/tmp/harmonia-win-build.XXXXXXXX)
mkdir "$harmonia_build_root/tmp" "$harmonia_build_root/cache"
TMPDIR="$harmonia_build_root/tmp" \
GOTMPDIR="$harmonia_build_root/tmp" \
GOCACHE="$harmonia_build_root/cache" \
mise run native-build-windows-arm64 -- --source-archive /path/to/fixed-source.tar.gz
```

`/var/tmp` 也须先确认确为磁盘。源码目录、原生产物与后续 Go 构建输出同样不要放在接近内存上限的 tmpfs；后续编译命令继续使用同一组目录。已有库与工具链可复用，不能为清内存删除唯一产物或无关目录。具体失败与修复证据见 [Windows 构建存储验证](../docs/WINDOWS-NATIVE-BUILD-STORAGE.md)。

## 构建静态库

在 Linux ARM64 新测试目录执行。显式传入已经存在、位于固定提交且没有跟踪改动的 BoringSSL Git 源码；入口不会重置该目录。

```sh
cd pairing
mise run native-build-windows-arm64 -- --source /path/to/fixed-boringssl
```

也可以传入固定提交的 `git archive --format=tar` 归档或其 gzip 压缩。压缩仅用于减少传输量；入口有界解压至固定 249630720 字节，并核对原始 tar SHA256 `0f0e21f670dd6c06a5ff9fc8a83748aeb959c6ca7ea4cb0ff8c62c9d88aa4002`。

```sh
mise run native-build-windows-arm64 -- --source-archive /path/to/fixed-source.tar.gz
```

入口在遵循 `TMPDIR` 的独占 `harmonia-bssl-windows-arm64-*` 临时目录下载官方工具链，先校验 SHA256 再执行。固定归档经成员路径检查后使用 GNU tar 流式解压。CMake 构建 `crypto` 与 `crypto_test`，并行数为2；检查四个 SPAKE2 符号前缀、ARM64 PE 与系统 DLL 边界。工具链、上游源码和失败日志保留在私有临时目录，不写系统 PATH，不运行安装器。

默认静态库输出为忽略目录 `native/windows-arm64/libcrypto.a`，附带许可证和私有构建记录。已有输出目录会被拒绝，不自动覆盖；已有公共头文件必须与固定源码逐字节一致。临时工具链清理后须重新构建。二进制与私有记录均不提交公开仓库。

## 链接与执行项目测试

```sh
mise run test-windows-compile
mise run test-default-cross
```

交叉链接入口核对固定构建记录和静态库 SHA256，使用同一工具链的 `libc++`、`libc++abi`、`winpthread` 静态库及 Windows `ws2_32` 系统库。不会混用 MSVC 或另一套 MinGW 产物，也不会用禁用线程绕过链接失败。它只生成测试 PE 并记录“Windows 执行未跑”。

在 Windows 来宾运行时，须把公开的 `testdata/pairing-application-v1.json` 放在测试工作目录的 `testdata/` 子目录。PowerShell 参数应明确引用：

```powershell
& $pairingTest '-test.v' '-test.count=1'
& $upstreamCryptoTest '--gtest_filter=SPAKE25519Test.*'
```

不使用真实账号、凭据或环境变量进行测试。测试输出只含断言和合成元数据，不输出短码、通道钥或消息内容。

## 已取得的结果与限制

本轮使用公开 core 提交加候选源码的隔离副本，实际完成固定工具链 SHA 校验、静态库构建与 Go1.26.4 CGo 链接。Windows ARM64 来宾中项目配对包 11个主测试及12个上下文字段子用例全部通过，包含错误短码必须得到 `ErrConfirmation`、未确认不得取钥、反射、单次使用、过期与跨会话回放。新构建的上游 SPAKE2 六项测试也实际通过，exit0。

此前一次解压进程被内存限制终止，之后改用流式解压；大归档传输改为压缩有界流。测试启动曾因 PowerShell 参数未引用、工作目录缺测试夹具失败，随后只修测试执行环境并保留原断言，完整重跑通过。失败日志与产物 hash 保留在任务私有记录，未纳入源码。不能把首轮失败记为通过。

交叉链接任务入口通过，默认配对包测试通过。默认关闭构建中的 Darwin ARM64、Linux AMD64 通过；Windows AMD64 在2GiB测试环境先后两次被 cgroup 内存限制终止（第二次已限定并行数为2），这两次记为资源失败，Windows ARM64 默认构建尚未跑。失败记录保留，不扩大 VM 或通过修改断言规避。当前用户直接打开 Vault 的关闭门槛测试已加入，但本次记录时其 Windows 执行尚未完成。

Windows ARM64 的 Go race detector 尚未运行；编译成功不能代替运行证据。此结果没有验证完整 Windows CLI 配对或系统服务，也没有生成 Linux 预制可信资料用于代替 Windows 入网。

## 正式 CLI 联合验收计划

1. 在新合成测试账号中使用管理员保护的固定配置、二进制及专用 virtual service SID。当前用户 CLI 只通过 OS 认证 IPC 登录/配对；系统服务独占加密 Vault、设备钥与后台状态，SYSTEM broker 只操作目标用户注册表环境。
2. CLI 发送凭据前验证服务端 exact SID、保留的 PID/process handle 与受保护映像；服务读取完整帧后核对客户端 exact SID、PID、映像和最后消息的线程 token。错 SID/错误映像、竞争管道和远程连接必须拒绝。默认 token 查询 ACL 如不足，先回报并审阅最小授权，不放宽身份校验。
3. 使用合成 HTTPS 账号与真实管理端 PAKE 确认，Windows 服务本地产生新设备钥。短码不发服务器；通过双方确认、精确授权与双签回执后才保存可信上下文。未知提交结果查询原 ID，不重签或生成替代资料。
4. 清除短期会话后启动服务，以设备持钥 boot 验证和同一受验证 Pull 下发；CLI 关闭后服务继续。通过实际 RO 拒写、RW 在线提交后 Pull、暂停授权投影、撤销/到期及逐键恢复验收。
5. 退出账号先取消并等待旧 worker/pair job，按 epoch 丢弃旧结果、恢复配置并清相关 slots。停服必须完整 drain，不能将失败/强制终止记为干净停止。

当前用户直接打开 Vault 的 Windows 登录/配对入口保持关闭，正式 daemon gate 也保持关闭。上列联合链通过并经审阅后才能调整入口状态；本切片不安装服务、不重启 VM、不配置 CI/CD、不发布安装包或 Release。

参考：[LLVM-mingw 官方项目](https://github.com/mstorsjo/llvm-mingw)、[固定发行资产与 SHA256](https://github.com/mstorsjo/llvm-mingw/releases/expanded_assets/20260922)、[Go CGo 文档](https://pkg.go.dev/cmd/cgo)。
