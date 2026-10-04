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
