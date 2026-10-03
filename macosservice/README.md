# macOS 有限服务安装入口

`harmonia-macos-service` 以普通 `sudo` 执行四个固定动作：`install`、`start`、`stop`、`uninstall`。首版仅新装，不升级或覆盖旧安装。它不是安装包，不安装宿主默认环境，不采集账号密码，不修改系统 CA，也不包含测试观测器。当前仍是实验性源码；此安装入口的真实 VM 安装、卸载与断电验收尚未执行。

构建和合成回归：

```sh
mise run test-macos-service
mise run build-macos-service
```

## 新装

必须明确目标用户名、规范十进制 UID 和主 GID，且系统按用户名与按 UID 查询都一致。非 root 目标账号不能借安装器读取别人的钥匙。程序来源必须是管理员已核验的 root-owned 普通单链接文件，路径及其祖先不能是符号链接、普通用户可写或带扩展 ACL；明确 SHA256 绑定复制的同一 FD 内容。安装器不执行来源程序做版本探测。

以下只说明参数，账号与摘要均为脱敏占位，必须先人工核对对应实际材料；不要直接在宿主执行样例：

```sh
sudo /root-owned-tools/harmonia-macos-service install \
  --user example-user --uid 10001 --gid 20 \
  --binary /root-owned-tools/harmonia --sha256 '<已核验的64位小写SHA256>'
```

可选 `--ca-file /root-owned-tools/self-hosted-ca.pem` 只接受公 CA 证书并复制到本实例目录。没有该参数时继续使用系统默认 TLS 根；有参数时正式 CLI 仍验证正常证书链和主机名。不会安装系统根或使用证书绕过。

固定布局：程序与安装收据在 `/usr/local/lib/harmonia/<UID>`，root 所有；配置在 `/Library/LaunchDaemons/org.harmonia-vault.user.<UID>.plist`，root 所有；状态在 `/Library/Application Support/Harmonia/<UID>`，目标 UID/GID 所有、0700。软件机器钥由正式目标用户 CLI/daemon 生成，0600；安装器不生成或迁移机器钥。共享 root 父目录不能由目标用户修改，且须让目标主 GID 或其他用户具有读和执行权限，以便正式 Vault 打开目录。安装器不自动放宽既有祖先权限；来源目录可保持管理员私有。状态目录不承担 root 删除路径的授权。

安装在 plist 发布前持久禁启动，重启也应保持禁启动；不使设备可信。安装成功后明确输出程序和状态路径。以目标用户在该状态目录执行正式 `login`、`pair`，只在手机完成确认后执行 `start`。普通交互密码由 CLI 终端读取；管道模式须显式 `--password-stdin`，不放命令行或环境变量。真实原生配对需要含已核验 BoringSSL 的正式 CLI。

```sh
# 以下由目标用户执行，并明确自己的 HTTPS 服务和管理设备 ID。
/usr/local/lib/harmonia/10001/harmonia login \
  --local-directory '/Library/Application Support/Harmonia/10001' \
  --local-user 10001 --server https://vault.example.invalid --email account@example.invalid
/usr/local/lib/harmonia/10001/harmonia pair \
  --local-directory '/Library/Application Support/Harmonia/10001' \
  --local-user 10001 --certificate-version 3 --approver '<可信管理设备ID>'
sudo /root-owned-tools/harmonia-macos-service start --user example-user --uid 10001 --gid 20
```

使用自托管 CA 时上述 login/pair 必须明确同实例的 `--ca-file /usr/local/lib/harmonia/10001/ca.pem`。恢复来源管理设备需要明确证书版本 4，连续恢复 DAG 来源明确版本 5，不能降级或自动回退。`start` 在目标 UID 下运行正式 `local-enrollment-check`，核本地已完成签名收据/来源账本，先持久保存本次 Start 授权再 enable/bootstrap；空安装、待完成配对、坏材料或检查失败不启动。此本地结果不证明当前在线授权，daemon 的 Boot 仍须检查服务器当前权限。不会绕过磁盘解锁，也不依赖只能登录后解锁的 Keychain；软件钥不代表硬件保护。

## 持久启停与部分安装

每个 UID 另有 root:wheel 0600 `/usr/local/lib/harmonia/<UID>.launch-control.json`，绑定随机 installationID、receipt v2、公程序/CA 摘要以及逐项创建的精确 inode。没有本工具权属却已有同 label 的显式 disabled 条目（true 或 false）或未知已加载 job 时拒绝；不收养旧配置，不读写其他 label。官方 print-disabled 只能查询域，结果仅进入有界进程内缓冲并严格投影本 label，不输出或存储无关配置。

对象在可信共享 root 父目录中完整建立、同步并关闭，先持久记录其 stage/最终父目录和 inode，才 exclusive rename。未记录的空、截断或完整 stage 保持原样，不构成授权；普通 Install 可继续同身份已记录创建，不能换 inode 或覆盖未知对象。尚未发布意图的普通创建失败只取消此前已记录本次对象；记录或 rename 回应不明则保留，由普通 Install/Uninstall 读取实际持久记录恢复。部分 Uninstall 反序清本次精确 inode，state 只允许为空；出现未知用户资料则保留。共享父目录和未引用 stage 不自动清理。

Start 的入网检查成功后才持久保存 start-authorized，再 enable/bootstrap。此后断电造成重启自动加载属于已明确授权 Start，不能称为未 Start 绕过。Stop 和 Uninstall 都先持久保存禁启动意图并 disable，再正常 bootout 和等待。完整匹配但没有 PID 的非 starting job 也只能正常 bootout、核 absent，再取得适用已有 owner 锁；不能把缺 PID 当作已退出。事务目录已冻结时不依赖 IPC，可正常停原 job 后按 preparing/cleanup-authorized 继续。

卸载后保留 removed-disabled 权属、永久协调锁以及本 label 的 disabled=true；不会全域 reset 或删除未知控制项。同身份下一新装获得新 installationID，仍禁启动，只有显式 Start 可以 enable。首版不支持旧收据升级。上述启动门的真实 launchctl/VM 验证尚未执行。

## 卸载

```sh
sudo /root-owned-tools/harmonia-macos-service uninstall --user example-user --uid 10001 --gid 20
```

正常运行中的本实例先以目标 UID/GID、空附加组和受限环境执行正式 IPC `logout`，再核受控 PID、bootout、确认 job absent，并有限等待此 PID 真正退出。原本已经正常 stop 的实例不重新启动；未启动但已经登录/配对的状态，使用同一正式 `logout --offline-local`。严格空状态没有任何材料或 IPC，直接进入精确清理，不创建机器钥、Vault 锁或账号。

每个 UID 有一个永久 root:wheel 0600 协调锁 `/usr/local/lib/harmonia/<UID>.control.lock`，串行保护四个安装动作。不存在时用独立随机 stage 与 exclusive rename 原子建立；内容为空，不能当成设备可信证明。卸载记录 `/usr/local/lib/harmonia/<UID>.uninstall.json` 与目标状态隔离，包含固定身份、root 安装摘要/inode、有限清理计划和持久下标，不包含账号值、私钥或 token。该记录在任何目录冻结前持久保存；有未完成记录时拒绝安装和启动，普通 stop 可以安全停原服务，普通 uninstall 继续同一事务。

状态/IPC 目录收紧为 root 0700，完整复检后取得所有适用的已有 owner 锁。非空状态须有 Vault 锁，存在 IPC 则也须有 IPC 锁；缺锁或忙锁保留材料。正式离线退出须先释放本次 owner 锁并恢复目标目录权限，成功后再一次核服务、冻结、复检并取锁，确认 device/session/trust/writes/recovery.dag 账号 slot 全部实际缺失。期间 CLI 新登录/配对或出现未知对象会停止，不能靠 basename 白名单删除新账号。

完整清理计划持久授权之后，才逐 inode/属性/摘要删除。记录只接受此前已清项目和当前已授权项目缺失；未来项目提前缺失、新 inode、新内容或未知条目都停止。删除中断后同一 `uninstall` 从持久下标继续，不重新运行 logout、登录、配对或服务。安装收据、程序目录删除并同步后，先持久保存 removed-disabled，再最后删除外部卸载记录；协调锁、禁启动权属和共享父目录保留。不会递归 `RemoveAll`、根据 target 文件选择 root 路径，或提供 force/升级。

记录更新通过 no-follow 随机 0600 stage、文件同步、原子 rename 和父目录同步。崩溃留下的空/截断/完整未引用 stage 都不是授权，也不阻碍固定记录重试；它们保留供管理员另行核对，没有自动垃圾回收。不猜删未知暂存文件。若最后记录已删但目录同步/关闭失败，返回错误；下一调用必须核永久 removed-disabled 权属并在可信父 FD 上确认缺失、同步和关闭后才能成功，不能仅据安装全缺失自造结果。

活跃 sh/bash/zsh 使用公开 POSIX cleanup：整个固定状态目录已消失且父目录仍可访问时，由该 shell 自己逐 key 恢复；单一片段暂缺不触发恢复。已有进程 env 不能由外部强制改变，sh 需显式刷新，bash/zsh 在 hook 时刷新。安装器不自动写 shell 配置。本入口的新 Mac shell 生命周期、真实 launchctl/drain、完整 VM 安装/停止/卸载与断电仍未验收，不能称生产可用。

此项目采用 MIT。

v7 输出适配将官方 stderr-only 的本 label 不存在诊断与未知错误分开，保持有界进程内缓冲；部分取消目录最多读取 128+1 项，超限保留并停止。定向实际结果与未跑范围见 [v7 适配验证](V7_ADAPTER_VALIDATION.md)。

## 最新根复验快照

在公开 core `eef6713` 加本安装器的隔离副本，两个包258项race全部通过（10.511秒），vet与Darwin arm64构建通过；20包消费者只编译、零测试通过。产物与v7候选相同。源级发现的stderr丢失和取消目录枚举上限已修；宿主服务未修改，正式安装器VM仍未跑。[机器证据](evidence/root-validation.json)。
