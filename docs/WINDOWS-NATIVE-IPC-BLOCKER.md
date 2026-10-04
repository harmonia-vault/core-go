# Windows 原生候选安装与普通用户 IPC 阻塞

2026-10-04 UTC。实验性候选；P7 未完成。仅使用已有隔离 Windows ARM64 VM、合成标准账号、合成 HTTPS 服务与环境变量。没有改账号组、ACL、服务所需权限、代理或系统信任根，也没有使用旧 token broker、S4U 或 Task Scheduler 路径。

## 固定产品与修改

安装的原生 CLI 来自 core `b29fad11ed1dee9cd1c745bfb9bfcb2134bb5f2c`，Go 1.26.4、CGO1、`harmonia_boringssl,harmonia_windows_account_candidate`，SHA256 `171e0accb99a7d3b3c03c714f2cba44341afcff0b58f8f4f0571f3600c2ff30a`。此前原生构建问题见 [构建记录](WINDOWS-NATIVE-BUILD-STORAGE.md)。

本次公开代码仅修复正式安装器的显式再次启动：正常 stop 会产生 `stopped-disabled` 收据，原判断只允许 `installed-disabled`，导致正常停服后无法再次 start。现在仅在服务确实 Stopped/Disabled、收据完整且没有 pending 操作时接受该状态。运行中、未知状态、不匹配启动类型和不完整收据仍拒绝。原有受限的中断 start 续办规则保留。没有新增自动重试。

修正后的安装器 SHA256 `43f3a5e9fd76f4767c39ffd4eb555c27d9a5a342e583d538c445e836e1d1d0e6`。CLI 映像没有因此重建，不能将两者混为同一个源码快照。

## 本次实际结果

| 动作 | 结果 | 证据与限制 |
| --- | --- | --- |
| 两项收据状态定向测试 | PASS | 1.803 秒；覆盖显式停服后 start 和原有中断 start 状态边界。 |
| 正式 stop | PASS | 25.244 秒；Stopped/Disabled。 |
| 第一次升级前置检查 | FAIL | 固定 guard 在写入安装前拒绝；诊断确认测试 CA 的 ECDSA 参数不被 Go x509 接受。 |
| Go x509 生成合成 CA 后升级 | PASS | 11.650 秒；固定旧/新摘要、持久备份、完整收据；保留已有 vault。合成 CA 仅用于该实例。 |
| 正式 start | PASS | 26.696 秒；Running/Automatic，pending 为空。 |
| 服务回读 | PASS | 10.394 秒；固定原生映像、目标普通账号、Session 0、profile hive 与收据匹配。device/session/trust 三槽为空。 |
| 普通桌面测试传输 | PASS | 目标账号、非管理员、交互会话与实例 CA 核验通过；合成密码仅经测试 TLS 和 stdin 使用。 |
| 正式普通用户 CLI login | FAIL | exit 1；后续直接执行正式 CLI status，得到 `IPC local identity mismatch`。没有接受为配对通过。 |
| 普通用户只读 API 诊断 | FAIL | 配置读取、服务 SID、SCM 与服务状态查询通过；`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` 返回 Win32 5，尚未到达服务 token 查询。 |
| 真实 CLI 配对、设备 Boot/Pull | UNRUN | 被前述 IPC 身份检查阻塞。管理端夹具请求不算 Windows 设备请求。 |
| 携带设备凭据的无人登录重启 | UNRUN | 不重复已通过的空账号重启；该结果不能替代凭据自动认证。 |
| 正式离线恢复与卸载 | UNRUN | 本次没有将夹具清理充当产品卸载或原值恢复。 |

探针只执行现有产品校验所用的读取 API，输出固定阶段、数值错误码和布尔结果；没有读取秘密、复制 token、模拟登录或改变权限。当前只能确认查询进程被拒绝，尚未确认 Windows 进程权限的完整成因。不扩大权限或跳过 peer 校验；后续必须解决普通 CLI 对真实服务的认证合同，并定向验证后才能继续配对。

原普通账号 DPAPI/槽绑定与空账号无人登录启动证据沿用 [v9 记录](WINDOWS-SCM-V9.md)。不同版本的这些局部通过不能拼成当前产品全链通过。测试传输首轮自身的 nil-map 失败另行保留，修正测试传输后才取得正式 CLI login 的实际失败。原始截图、VM/账号标识、运行数据库、测试密钥和私有执行脚本均不公开。

## 后续只读定位：同账号的不同登录上下文

实际普通用户探针直接连接正式命名管道，并用同一已依赖的 go-winio 句柄调用 `GetNamedPipeServerProcessId`。pipe PID、前后 SCM PID 完全一致，pipe 服务会话为 0。独立只读管理观察确认该 PID 的安装映像、目标普通用户 SID、已启用的精确服务 SID 和 Session 0 均正确。普通查询方同一用户 SID、非管理员、Session 1；双方登录 SID 不同。因此这是操作系统拒绝跨登录上下文的查询，不是查错进程或用户 SID 不匹配。管理观察仅用于定位，不能替代产品中的普通用户认证。

实际服务进程 DACL 仅允许服务登录 SID 完全访问和管理员 `0x1400`；普通交互账号既没有该登录 SID，也不是管理员。服务 token 的 DACL 允许 SYSTEM/精确服务 SID 完全访问、管理员查询，并将 owner 权限限制为 READ_CONTROL。该普通账号即使是 token owner，仍没有 TOKEN_QUERY。

当前 `OpenProcess` 请求已经只有 `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`)。[OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) 会按进程安全描述符检查它；[QueryFullProcessImageNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew) 和 [OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken) 都需要该权限，后者还独立检查 token 的请求权限。降低到零权限不能完成现有身份核验。

保持当前全部认证条件，至少需让精确目标用户 SID 获得该服务进程的 `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`) 和服务 token 的 `TOKEN_QUERY` (`0x8`)。这是尚未授权的新权限，本次没有添加。反向客户端进程查询及完整双向认证尚未复验，因此不声称上述两项单独就足够。没有启用 SeDebugPrivilege、复制 token、改变安装/系统 ACL 或跳过失败。

核对了 [Microsoft go-winio v0.6.2](https://github.com/microsoft/go-winio/blob/v0.6.2/pipe.go) 的真实句柄与 SQOS 处理，以及 [.NET NamedPipeClientStream](https://github.com/dotnet/runtime/blob/main/src/libraries/System.IO.Pipes/src/System/IO/Pipes/NamedPipeClientStream.Windows.cs) 的 CurrentUserOnly owner 检查。后者只保证 owner 相同，不能直接替换本产品的固定 SCM 服务、映像和服务 SID 约束。尚未找到经过验证、保留这些约束且不需新权限的替代方案；Windows 产品登录/配对仍然阻塞。此次未改产品代码或重跑已通过的升级。
