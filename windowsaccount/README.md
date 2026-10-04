# 标准 SCM 普通用户服务候选 v9

普通账号服务、当前用户 CLI、受保护安装与逐键恢复后卸载的实验候选。默认构建关闭，仅显式 `harmonia_windows_account_candidate` 标签开放入口。v9 已在合成 Windows ARM64 VM 中由标准 SCM 启动至 Running/Automatic，并核验指定普通用户 SID、Session 0、固定映像与已加载 profile。初次启动测试已有交互登录；后续一次空账号服务的无人登录自动启动也已通过，但凭据入网和完整生命周期仍未完成。详见 [v9 验证记录](../docs/WINDOWS-SCM-V9.md)。

## 身份与系统边界

SCM 正常使用配置账号登录并自动加载其用户 profile，服务直接打开本人的 `HKEY_USERS\<SID>\Environment`；不调用 LoadUserProfile 或取得另一身份的运行 token。[Microsoft Service User Accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts)

安装器使用正常 `CreateServiceW` 的 `.\UserName` 和密码，以 own-process / disabled 创建。完成固定配置、服务 DACL、required privileges 与 SID 设置后才允许 `start`；每次操作还回读 SIDType、唯一 required privilege 和 SYSTEM/Admin/目标用户的精确三项 DACL；实际 Running 后才改成 automatic。[CreateServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)

SCM 把服务密码存入 LSA 的受保护区域。候选安装器从专门的标准输入读取可清零 buffer，不把密码放入参数、环境、配置、receipt 或日志；不能声称 Windows 不持久保存密码。账号改密码或密码过期会影响服务登录，当前没有自动维护密码或修改密码策略的功能。[Service Record List](https://learn.microsoft.com/en-us/windows/win32/services/service-record-list)

服务登录需要 `SeServiceLogonRight`。预检枚举直接权限、间接本地组及 Everyone/Authenticated Users/Service/Local account/Local 公共 SID；发现 deny 即令安装失败，永不删除 deny。已有直接/组 allow 不重复添加；缺失时只添加该账号这一项，记录安装前直接权限和本次差量。卸载只有在本服务已移除、完整枚举确认无其它服务用此 SID、确系本次新增且该项仍存在时才删除这一项。策略读取/身份解析结果不明一律停下，不能把未知当作零。这不是任意域/GPO 策略的完整建模，实际 SCM 正常登录仍是权威拒绝门。第三方管理员并发改动没有跨 SCM/LSA 原子事务，不能保证消除该竞态。[Account Rights Constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants)

安装器当前限定 SYSTEM（供已授权安装执行上下文使用），不尝试提权。普通账号服务只保留 `SeChangeNotifyPrivilege`，以 SERVICE_SID_TYPE_UNRESTRICTED 启用本服务 SID 作为组标识（未启用 restricted SID 列表）；不给账号管理员、Backup、Restore、Debug 或 Impersonate 权限。运行验证要求真实 SCM 服务、exact 用户 SID、Session 0、非管理员、SERVICE 组和本服务 SID 组。组中出现管理员（包括 deny-only）也拒绝。

## 完整的源码路径

- `Plan` 约束本地 SAM 普通账号和 SID 派生的固定目录、exe、config 与服务名；所有既有实例冲突停止，不覆盖。
- `Install` 创建 SYSTEM/Admin 保护的 exe、config、可选测试 CA 与 journal；目标用户仅有读取/执行权。状态根归本实例，vault 仅目标用户和 SYSTEM/Admin 可写。源文件必须是单链接非 reparse 普通文件，且符合审阅 SHA256 和大小上限。
- `install.json` 在每个权限/SCM 步骤之前原子写 pending；密码不入盘。创建失败保留明确阶段/固定错误码，不猜测删除。操作锁是排他文件 handle，进程退出释放，残留锁文件可重开。
- `start` 回验固定服务命令及账号 SID，正常 StartService，等 Running 后启用 automatic；`stop` 先 disabled，再 Stop/drain。start 或 stop 结果不明可通过 stop 重新核实收敛；不允许用它跳过不完整安装。
- `harmonia daemon-user-service --config ...` 使用现有当前用户 DPAPI/vault/provider、sync owner、PAKE v2–v5 与账户 owner。已有虚拟服务模式的 exact token-user 校验没有放宽。
- `harmonia <command> --windows-account-config ...` 支持 login/pair/pair-status/pair-cancel 及现有环境命令。密码 SHA256 的 32 字节只经认证后的本机 IPC 传给同用户 owner；Vault 不向 CLI 导出。共享写只提交云端，仍经统一下发流更新本机。
- IPC 在发凭据前固定受保护配置、映像和 server process handle，核 exact 用户 SID、本服务 SID 及 SCM PID；server 核调用者 SID、同一受保护 CLI 映像，并对最后一个 pipe 消息做 identification-level 身份核验后立即 Revert。此短暂 IPC 身份核验不用于启动进程、借用登录 token 或加载 profile。
- `restore-user-service` 只在服务确实 stopped+disabled 后，由同用户打开既有加密存储；持久 logout、清账号 slots、逐键恢复并保留注册表类型、提交空托管状态后写本地恢复摘要。摘要只是同用户交接记录，不是云信任或对抗本用户的证明。
- `remove` 必须验证恢复摘要、账户 slots 已清和目录精确白名单；先删除服务，确认其消失，再撤销自有新增权限，最后删除本实例精确叶文件和空目录。不会删除用户、profile 或无关环境。

## 关键故障语义

Windows provider 在注册表变更前持久保存待通知状态；空 patch 或重启仍会重试通知。SendMessageTimeoutW 返回零不能当成功。Session 0 的通知实际效果仍待原生验证，现有进程的环境不会被外部强制改写。

释放变量时保留原值及 REG_EXPAND_SZ 类型，直到引擎最终提交确认不再管理该 key。引擎最终 Save 失败、外部编辑和 provider 重启不能把外部值误当原值；下一次真正接管才重新记录基线。新增故障回归覆盖了这条完整路径。

**尚未完成自动恢复的边界：** 部分 install 中断、SCM 删除后/文件清理途中崩溃会留下 receipt；部分 remove 阶段不能自动重入，必须先按 receipt 和实际资源审阅后收尾。任何 pending 不会被当作成功。当前没有崩溃后自动重启的 SCM recovery action，也没有密码变更维护入口。这些属于产品缺口，不是通过编译即可忽略的事项。

## 验证与下一步

已有宿主组合测试覆盖 platform/localstate/localipc/windowsaccount/cmd owner 的 race 测试；Windows ARM64 CGO0 CLI 与安装器交叉编译、Windows vet 仅证明构建与静态检查。CGO0 CLI 不含 native BoringSSL SPAKE2，不能用于声称真实 PAKE 成功；需用仓库既有固定工具链构建 native 版本。

标准 SCM 安装和 v9 启动、普通账号进程身份回读已通过。此前 v6/v8 的启动失败保留为历史失败，不能把它们改记通过。v9 CGO0 二进制不包含原生 SPAKE2；当前用户 IPC 联合凭据流程、HTTPS login/PAKE/Boot/Pull、持有可信设备材料的无人登录重启、完整纠正/到期/撤销、logout/drain 和卸载仍未取得此候选完整验收结果。原有独立组件测试仅作为组件证据复用。默认产品门槛保持关闭，不宣传生产可用。

## v3：撤销账号权限前的完整使用者核对

SCM 的 EnumServicesStatusEx 会静默省略调用者无 SERVICE_QUERY_STATUS 的服务，因此其零返回不能证明没有其它使用者。本候选改为只读遍历 HKLM\SYSTEM\CurrentControlSet\Services 的全部直接子键，记录 Type、ObjectName、字段存在性、子键和根键 LastWriteTime；逐个 OpenService 回验 SCM 配置与状态类型，Win32 服务的登记账号和 SCM 账号各自解析 SID 后必须一致，再用第二份完整注册表快照检查增删/变化。拒绝查询、未知类型、未知账号、两边不一致或快照变化均保留新增 right，receipt 明确记录 service-removed-right-check-incomplete / verify-other-service-users，退出非成功；不会改注册表 ACL 来读取。

已回验类型一致的 driver 不使用普通服务账号登录；没有 Type/ObjectName 的配置键只有在 SCM 明确 ERROR_SERVICE_DOES_NOT_EXIST 时才排除。传统 Win32 服务缺省账号按 LocalSystem 处理；每用户服务模板/实例的 bit64/128 有特殊用户上下文，此窄候选尚未证明其 service-logon-right 语义，故保持未收尾，既不声称它们必然需要该 right，也不默认它们无关。这可能使实际 Windows VM 卸载保留权限和 receipt；这是候选待补的判断能力，不是永久产品设计。

前后快照只能发现可见变化，不能消除最后一次观察与 LSA 修改之间的第三方管理员竞态；没有跨注册表/SCM/LSA 的原子事务。本候选不使用已无实际锁定作用的 LockServiceDatabase 来掩盖该限制。

官方依据：[SCM 访问权限与枚举省略](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)、[服务数据库](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)、[每用户服务](https://learn.microsoft.com/en-us/windows/application-management/per-user-services-in-windows)。


## 本地 SAM 身份解析

SCM 的 serviceStartName 仍使用系统支持的 .\user。安全验证不把该登录简写或裸用户名直接传给 LookupAccountName：先从 GetComputerName 取得本机名，查询真实 machine\user，并核对本机 domain、SidTypeUser 和计划中的 exact SID；再用同一 SID 的 LookupAccountSid 反向确认本机 domain、kind 与完整用户名。Windows 名字比较不区分大小写，不允许额外域/分隔符或外域同名替代。SCM 配置回读只接受本机限定名或原 .\user 形式，再走上述双向校验。任何查询/匹配失败保持关闭。

服务使用者盘点遇到 .\local-user 也做本机双向解析；其它分支和未知使用者保留权限的规则不变。本修改来自合成 Windows 只读预检对当前旧账号名查询失败的观察；不能据此恢复已回收的先前安装错误，或宣称新安装已通过。

依据：[LookupAccountNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountnamew)、[LookupAccountSidW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsidw)、[CreateServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。

## 显式启动续办与数值结果

LastStart 可选收据字段分别记录 change-demand、resume-manual、start-service、wait-running、enable-automatic，只有固定阶段、成功布尔、Win32 numeric code 与 SCM 状态/退出码，不保存原始错误字符串。CodeKnown=false 表示错误没有可确认的Win32码；StatusRead=false 表示当前Config/Query失败，零值不是实际状态观察。每个阶段结果先持久化，失败保留pending，不自动再Start。

新安装仅允许已创建的 installed-disabled/pending空、SCM当前Stopped+Disabled。显式同实例续办只覆盖 installed-disabled/pending=start-service 且当前Stopped+Demand（Manual），旧v4没有LastStart也可读取；必须重新通过相同配置/SID/DACL/Config2与文件哈希验证。Running、未知状态、Auto、其他pending或未知LastStart阶段均拒绝。此路径不重新Install、读取密码或增删账号权限，不等于通用崩溃恢复。写入LastStart后，后续Stop/Remove必须用能识别该字段的新版installer；配置和已安装CLI可保持原哈希。


## v6：先连接 dispatcher，再执行完整初始化

入口仅从严格规范的固定配置路径取得服务名，立即调用 svc.Run。路径字符串只供 dispatcher 路由，不建立信任；完整 LoadConfiguration、父链句柄固定与 ACL、配置内服务名、VerifyOwnService、服务 SID 和可选 CA 验证移入 handler。全部通过前不打开本地钥匙、不启动 IPC 或网络。交互启动仍由标准 SCM dispatcher 拒绝，未添加其它登录或 token 启动路径。

初始化失败通过 SCM 的服务特定退出码报告固定阶段：0x4801 配置/固定路径与受保护父链，0x4802 自身服务身份，0x4803 服务 SID，0x4804 CA。未知后续错误仍返回 1，不输出原始错误或账号秘密。StartPending 保持既有 30000ms waitHint 和 checkpoint；Running 后接受 Stop/Shutdown，取消后等待清理完成。waitHint 不是强制结束任意阻塞系统调用的保证。

新共享父目录仅为 Builtin Users 加非继承 READ_CONTROL、FILE_READ_ATTRIBUTES、FILE_TRAVERSE（0x200a0），不给列举、内容、写入、修改 ACL 或所有权权限。SYSTEM/Admin 保持继承 FullControl。新建实例目录、配置和私钥依旧使用各自受保护 DACL；父目录的 BU ACE 不下传。已有父目录必须精确匹配该三 ACE 合同，否则失败，不隐式修改旧安装 ACL。现有合成 VM 的旧父目录仍为管理员专属；它与普通账号父链读取需求冲突是源码支持的假设，实际故障位置仍需下一次 SCM 阶段码证明。

宿主合同覆盖 dispatcher 先于初始化、取消/信任失败不 Ready 和有限阶段码。Windows ARM64 交叉编译只证明可以构建。两个原生权限合同用 AUTHZ_SKIP_TOKEN_GROUPS 固定值 2 和合成 SID 计算生产 SDDL，显式加入 BU；不使用默认 Authz S4U 路径、不登录、不创建 OS token、不启动身份进程。它们当前仅编译、未运行；即使计算通过也不能替代实际普通用户文件打开验收。

依据：[SCM dispatcher 初始化顺序](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw)、[Authz 跳过组解析的固定参数](https://learn.microsoft.com/en-us/windows/win32/api/authz/nf-authz-authzinitializecontextfromsid)。
