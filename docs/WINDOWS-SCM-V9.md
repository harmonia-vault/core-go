# Windows 标准 SCM 候选 v9 验证记录

本记录对应实验性源码，不是发布或生产可用声明。使用合成普通账号、隔离 VM；没有上传机器 SID、账号密码、私有路径、二进制、运行时 vault 或测试服务器数据。

## 改动与来源

v9 仅改变三个文件：`windowsaccount/config_windows.go`、`metadata_path.go`、`metadata_path_test.go`。祖先目录通过已依赖的 `x/sys/windows.NtCreateFile` 明确请求 `READ_CONTROL | FILE_READ_ATTRIBUTES`（0x20080），仅打开既有规范本地 DOS 路径。保持 owner/DACL、类型、reparse、加密属性、句柄持有和叶文件正文校验；不扩 ACL、账号组或服务权限。

标准 SCM 前置候选此前尚未公开，因此本分支同时收录已审的必要服务、安装、IPC、CLI 和逐键恢复实现。基于公开 `2aa0c48fbe2fdbfa5348e37d02c8ff69733a6b98` 整合，保留其后续恢复/DAG 功能和通知重试。唯一合并冲突为 Windows provider 字段块：同时保留 `notifyPending` 与 `reconcileTracked`。默认候选门槛继续关闭；不使用旧 Task Scheduler、S4U、token 复制或手动 profile 加载路径。

## 原 v9 实际证据（复用，不重复运行）

- 原源码清单 SHA256：`a37c4f04611aea99616bce4632d050c29bf2e710b97a5d0e27c60b27e3af0f15`。
- 原 Windows ARM64/CGO0 CLI SHA256：`8ebf0bf3c785d5aef2ad6cba96dedf973e7380e1ae015ecc50d720a8e652ad5e`。
- 路径合同测试：**PASS**，1.946022 秒；Windows vet：**PASS**，3.83843 秒；CLI 交叉编译：**PASS**，3.082093 秒。
- VM 一次性升级与启动步骤 01–06：**PASS**。标准 SCM 启动 7.609004 秒；读取 Running/Automatic、目标 SID、Session 0、固定映像和 profile hive 5.366293 秒。收据 pending 为空；没有修改 ACL 或身份。
- 上述实际意图/结果清单 SHA256：`fbb71629407713046a1d7df5e9a82f39f5f96fb984bb6199f3f59a1ddb34e5de`。
- v8 启动：**FAIL**，1066 / 0x48212005。OVERLAPPED 已存在仍失败，因此不把隐式 SYNCHRONIZE 单独认定为已证根因。
- 普通账号 DPAPI、槽绑定、服务身份和安装 ACL 的既有独立测试沿用原记录；不重跑整个矩阵。

## 整合边界

原 VM 使用上述 v9 固定二进制。本分支整合了较新公共主线，不能把原 VM 结果宣称为整合后全部代码的原生验证。新增整合检查仅验证恢复原值与通知重试的组合，并编译 Windows ARM64 候选；两项指定 Windows provider 测试 **PASS**（42.013 秒，含首次缓存编译），整合版 Windows ARM64/CGO0 候选编译 **PASS**（57.674 秒）。没有重跑原生矩阵；整合二进制尚未安装到 VM。

原始启动测试已有交互登录；后续补充的一次无人登录重启结果见下。CGO0 不含原生 SPAKE2，完整凭据入网仍 **UNRUN**；真实 PAKE、设备 Boot/Pull、完整停服/恢复/卸载和 P7 均未完成。不能以服务 Running 代替这些结果。

API 依据：[NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)、[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)。读取 owner/DACL 需要 READ_CONTROL，仅属性权限不足。

## 补充：一次无人登录重启（2026-10-04）

在固定合成 Windows VM、原 v9 已安装二进制上，只发出一次 `shutdown /r /t 0`；未强制关机、修改自动登录、ACL、账号或权限，也没有手动 StartService。重启请求返回成功。

重启后只读核对 **PASS**（24.731 秒）：启动时间已变化；服务进程创建于新启动周期，自动进入 Running/Automatic；指定普通账号 SID、Session 0、固定映像与安装收据一致；用户 profile hive 已加载。CIM 中普通账号交互登录为 0，开机后安全日志中的普通账号交互登录事件为 0，目标账号服务登录事件为 1；读取未达到 2048 条上限。没有图形登录或键盘输入。

重启前后 device/session/trust 三个凭据槽均不存在。因此通过项仅为 **空账号 SCM 服务的无人登录自动启动和初始化**；不是已授权设备的开机认证、PAKE 或 Boot/Pull 通过。原值纠正、停服、恢复、卸载也没有在本次重跑。

私有执行证据清单 SHA256：`68c5675df313d33d7a7d82ca9992f5a6866b3aa30313526abb916a97da0a57c0`。公开记录仅含脱敏结果，原始 VM 标识、服务实例路径和运行材料不上传。

## 凭据流程的剩余接线

现有安装仍是上述 CGO0 映像，配置没有合成 HTTPS CA，device/session/trust 槽为空。已检查旧固定升级助手：它仅接受此前失败的 `installed-disabled/start-service` 收据和 Stopped/Manual 状态，不适用于当前 Running/Automatic 实例；不能删除这些保护断言后直接重跑。后续需正常 stop/drain、针对精确旧/新文件及收据的可恢复升级、受保护 CA 配置，再从同用户 CLI 完成真实 login/PAKE、原 ID 确认和统一 Pull。不能用 SYSTEM 请求替代普通用户 CLI，也不能把另一机器生成的可信材料直接放入 Windows vault。

这里没有缺少用户真实密码，也没有请求真实凭据。剩余项是含原生配对的产品映像、安全升级与测试接线；本次没有进入账号、角色或变量业务矩阵。

## 原生凭据候选构建结果

复用已存在且哈希匹配的固定 BoringSSL Windows ARM64 静态库与 LLVM-mingw 工具链，未重建依赖、安装工具或下载替代版本。以本分支代码提交 `b29fad11ed1dee9cd1c745bfb9bfcb2134bb5f2c` 构建 `harmonia_boringssl,harmonia_windows_account_candidate`、CGO1 候选，限制 Go 并发为 2。

本次 **FAIL**：259.37 秒，exit 1，Go `runtime` 编译进程报 `signal: killed`。没有取得足够证据确认具体终止原因，不把推测的资源耗尽写成已证事实。没有重复构建、扩大 VM 或生成新 Windows 映像；含原生 PAKE 的候选安装、真实凭据流程和设备 Boot/Pull 均 **UNRUN**。原 v9 CGO0 服务保持运行，成功的空账号无人登录重启结果不受此构建失败影响。

## 后续构建阻塞已解决

以上两次编译失败保留为历史结果。进一步定位到 Linux 构建容器的 tmpfs 材料占用接近 2 GiB 限额；迁到既有磁盘、保持源码/工具链/资源限制后，含 SPAKE2 的 Windows ARM64 候选在 111.744 秒内构建通过，未新增 OOM kill。详见 [原因、上游资料与对照验证](WINDOWS-NATIVE-BUILD-STORAGE.md)。新映像尚未安装到服务，真实凭据流程、设备 Boot/Pull 与 P7 仍未完成。
