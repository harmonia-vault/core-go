# Linux 单用户 systemd 安装器（实验性）

本安装器最初在公开 `core-go 6d8178ae3116e6eb9dc4c1a9197c885c6a7687b1` 的独立归档实现 install、start、uninstall 协调器，未修改共享 CLI、密码学、手机或 GoMod。源码现已公开；隔离 Ubuntu 已验证原生10项和正式空生命周期，外层清理仍有保留的 FAIL，完整范围见文末与 [VM 记录](VM_VALIDATION.md)。真实入网后启服、重启和有材料卸载尚未验收，不宣称生产可用。

独立 root 命令 `harmonia-linux-installer` 仅管理明确 UID 的固定目录。日常 CLI 始终由目标用户运行。安装不是登录，systemd active 不是设备可信，也不是服务器授权成功。

```text
sudo harmonia-linux-installer plan --user lab --uid 10001 --binary-source /reviewed/harmonia --binary-sha256 <SHA256>
sudo harmonia-linux-installer install --user lab --uid 10001 --binary-source /reviewed/harmonia --binary-sha256 <SHA256>
# 目标用户显式完成真实 login/pair；安装阶段服务 disabled/inactive。
sudo harmonia-linux-installer start --user lab --uid 10001
sudo harmonia-linux-installer uninstall --user lab --uid 10001
```

可选 `--ca-source/--ca-sha256` 只能导入限长有效 CERTIFICATE PEM；拒私钥、未知块、header 和摘要变化，不改变系统 trust。参数拒未知、重复、位置参数与 root UID/GID；NSS 用户映射逐次核。计划输出无秘密，不扫描宿主环境、不自动导入任何变量。

## 安装与启动

固定程序 `/usr/local/lib/harmonia/<UID>/harmonia`，可选 CA 同目录；unit `/etc/systemd/system/harmonia-user-<UID>.service`；用户 Vault `/var/lib/harmonia/<UID>`；root 事务 `/var/lib/harmonia-installer`。公有祖先 0755，用户末级 0700，程序 root 0755、CA/unit 0644，root 记录/锁 0600 与 root 0700 父目录。共享父与管理 lock 不随一个 UID 卸载而删除；不写 shell profile，不创建公共 `/usr/local/bin` 链接。

先核原生 ELF、显式 SHA、无 file capabilities/ACL/硬链接；不会以 root 执行输入程序。receipt revision/固定创建清单先保存 intent，再 O_EXCL 创建或发布，再记录公开 dev/inode。程序目录先 root 0700；全部对象认证与 handoff intent 持久后才交给目标用户空 Vault，并把程序目录开放读取。unit 加 `RequiresMountsFor` 与固定卸载 guard 条件，不绕磁盘解锁，不开机创建新钥匙替代原钥匙。

独占文件发布用 Linux `renameat2(RENAME_NOREPLACE)`，没有 Linkat→Unlinkat 双链接窗口，也没有不安全 fallback。内核不支持明确 UNSUPPORTED。已确认的同安装 ID/对象临时名称在重试 install 时只接受 root 单链接固定 mode，重新复制并验完整摘要；不按前缀批量删其他临时文件。未知现存程序、unit、Vault、drop-in、alias、额外 enable 链接、影子 vendor unit 均拒绝覆盖。安装结束严格 disabled/inactive。

start 先核 root receipt、原 inode/摘要、固定 enable link 与 NSS，然后降实际 UID/GID、清附加组，用固定必要环境执行已公开的：

```text
harmonia local-enrollment-check --local-directory /var/lib/harmonia/<UID> --local-user <UID>
```

只有 exit0 与严格 `{ "version": 1, "localEnrollmentVerified": true }` 才能持久 enable intent，再 enable/start 本 unit。该检查无 HTTP/worker，只验证受保护入网回执和来源 ledger。服务随后实际 Boot/Pull 才逐次检查当前云端授权。启服检查实际 PID 的公开 UID/GID、零有效 capability 和 NoNewPrivs，不读进程 env。启服后 receipt 保存失败保留原 intent/link，同 unit 已 active 时可安全收敛 receipt；不假称重新完成在线授权。

## 卸载、并发与中断

root 管理 lock 非阻塞；持久 journal+guard 先于 stop。只停止本 unit；不使用 systemctl disable 的宽泛链接清除，也不 reset-failed。stop 命令超时、SIGKILL、非正常退出、未知属性均保留资料并拒绝。即使 PID0，也要核整个 cgroup v2 后代为空；v1 或异常读取拒绝。systemd show 使用固定属性与 --all，避免省略必要空属性；与系统路径检查均有界、拒 alias/drop-in/触发单位；未知 enable link 不删除。

正常 drain 后先严格检查有限文件类型/UID/mode/ACL/硬链接，freeze 用户目录和 IPC 为 root0700，然后非阻塞重取既有 vault.lock/IPC lock。非空目录缺锁不能新建锁来证明无 owner。busy 立即恢复用户目录、保留事务/资料，不杀其他 CLI。真正空、从未初始化的目录不构造 Vault、不产生 machine key、不执行 logout。

非空状态释放临时锁并恢复 UID 目录后执行成熟共享动作：

```text
harmonia logout --offline-local --local-directory /var/lib/harmonia/<UID> --local-user <UID>
```

只接受 exit0 和最终 `{ "version": 1, "localLogoutComplete": true }`，不启动 worker/HTTP。随后再次 freeze/relock，实际检查 device/session/trust/writes/recovery-dag 五个 account slot 全部缺失；若并发新登录留下任何材料，保留它并拒删。账户材料不进入 root 删除清单，安装器不解密或复制私钥。

权威读取会重新同步当前固定record文件及admin父目录；重试unlink后的absence也必须重新同步实际对象父目录，不能仅同步位于另一目录的journal。

cleanup-authorized 保存原对象身份后，最终锁保持至结束。仅有界固定 IPC、provider/state/机器钥/fragment/锁、空末级目录、精确 enable link/unit、程序/CA 能逐项删除。每次先保存 intent，再原 inode 核验、unlink/fsync，随后 removed；目录在子目录移除后仅允许正常 link-count 下降，inode/owner/mode 等仍精确。未知文件（包括 `.localkeys-*`）保留。

中断续做只读同一 journal。缺对象必须有原删除 intent；不能把历史 receipt 或缺钥匙推断为已退出。授权后不再执行可能已删除的 binary、不 thaw 用户目录；重新核所有剩余 inode、root freeze、account-slot 缺失和现存锁。单对象保存失败停住，不标完成。unit 删除后 reload 并核 not-found；程序最后；completed 持久后 guard、receipt、journal 依次精确移除，journal 最后。成功还须所有 Close 与 caller context 成功。

部分安装已完成发布但尚未记录 observed 可从原持久 intent、固定 root 身份及摘要收敛。**中断复制仍有精确临时文件时，卸载保留并拒绝；先以同源/同摘要重试 install 完成复制，再卸载。** 不能靠 uninstaller 泛删未知临时文件。未知记录、换 inode、手动缺文件无 intent、坏状态/权限、异常 stop、root 持久失败均关闭，不报成功。恶意 root/整个磁盘旧快照重放不在此保护范围。

成功不删除云账号，不宣称云撤销已完成；当前 shell 原值恢复复用已公开 POSIX fragment/hook。新版 hook 仅整 StateDirectory 消失时逐 key 恢复，无关变量不动；bash/zsh 下次 prompt，sh 显式 `harmonia_refresh`。已启动进程的 env 无法外部强制改，旧 hook 不追认新恢复能力，暂停/停服/崩溃本身不清配置。

## 检查与后续真实 VM

host race 验 Plan、固定状态/JSON/CAS、创建 intent/身份不可替换、部分安装清理 snapshot、精确 helper DTO、systemd 正常停服与进程记录。Linux 专用测试在新 root temp layout 注入 system-manager/helper 回应，验证真实 FD/ACL/flock/fsync/rename 与协调器中断；现已有10项实际内核通过，仍不当成真实认证或完整 systemd 产品链。

VM 验证分阶段进行：正式空安装/未入网 Start 非零/卸载已实际完成；真实 native PAKE 入网启服、完整重启且目标 UID 无登录、正常停止后有材料离线卸载与同 SSH shell 逐 key 恢复，以及真实持久删除断点/并发 owner 原事务重试仍未执行。只新合成 UID、账号、明确变量，不碰旧 VM/其他 UID 或宿主 env；没有 CI/CD、Release 或线上部署。精确 PASS/FAIL/UNRUN 和 artifact SHA 在候选外层证据中，不把后续计划算测试通过。

固定 show 使用 properties 模式：systemd v255 源码对不存在 unit 仍输出属性并返回0；status 的未知服务退出码没有被挪作安装成功。参见 [systemctl-show.c](https://raw.githubusercontent.com/systemd/systemd/v255/src/systemctl/systemctl-show.c)，实际目标 systemd 行为仍由 VM 验证。

早期冻结的检查历史（不覆盖文末最新结果）：host race 14主/57子（71 PASS、0FAIL、0SKIP），package 1.539秒/process 2.094秒；host vet 0.109秒；LinuxARM64 test-compile 0.546秒、command build 0.446秒、Linux vet 0.247秒均PASS。当时目标8个原生测试/实际systemd/全部VM为UNRUN。Phase1两FAIL和Phase2字段补丁编译FAIL均保留在私有证据，不删失败历史。

## 最新根复验快照

在公开 core `eef6713` 加本安装器的隔离副本，host71项race全部通过（5.524秒），host/Linux vet、ARM64安装器及Linux全部包构建通过。[根机器证据](evidence/root-validation.json)。较早固定base构建的真实Ubuntu续验为10/10原生PASS，正式空安装/未入网Start非零/卸载通过；外层组清理仍FAIL，最终账号与组实际均不存在且旧资源未变。原4PASS/5FAIL保留；完整结果与尚未运行的真实入网/重启范围见[VM记录](VM_VALIDATION.md)与[机器证据](evidence/vm-validation.json)。
