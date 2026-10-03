# 受保护的本机离线退出

macOS 与 Linux 的正式 CLI 支持显式本机离线退出，用于后台已经停止时恢复托管配置并清除本机账号材料。此命令不启动后台、调用 HTTP、注销服务器会话或删除云保险库；Windows 此入口明确不支持。它不能在正在持有 Vault 的后台或其它本机操作期间绕过所有者锁。

```sh
harmonia logout --offline-local \
  --local-directory /absolute/owned/vault \
  --local-user 10001
```

占位 UID 必须替换为实际执行账号的规范非 root UID；目录必须是该账号既有的规范绝对 0700 目录。macOS `/var` 与 `/tmp` 等别名不能代替已固定的实际目录路径。此动作只接受 `offline-local`、`local-directory`、`local-user`，不接受 CA、邮件、密码、fixture、其他 provider 路径或位置参数。原有不带此开关的 logout 仍走后台 IPC。

`OpenExistingEncryptedStateStore` 复用正式目录 FD、no-follow、所有权、mode、单链接、ACL 检查和非阻塞独占。不存在的目录、锁或机器钥不会被重新建立；空安装由安装器另行处理。错误 UID、锁忙、坏材料或不安全属性均停止。

同一 Vault 所有者生命周期内，尚未关闭的账户先持久推进本地 epoch、置 AccountClosed，并清共享明文、激活与 override；已经关闭时仅幂等完成剩余动作。复用当前 `wipeAccountSlots` 清 device/session/trust/writes/recovery-dag-v1，再使用固定同目录的受保护 POSIX provider 逐变量恢复。机器钥、已关闭的加密状态和 provider 恢复元数据仍保留给后续检查/卸载，不会授予旧设备信任。

退出专用 provider 只加载并验证，构造时不重写旧 Desired，也不在取消暂停时先下发旧值。所有 Desired 必须具有 Engine 原值记录，随后经过原有 Reconcile/Apply 恢复；没有记录或 provider/最终保存失败不报完成。只有账户关闭、缓存与恢复记录为空、最终 release 片段成功写入且 Store 正常关闭，才输出：

```json
{"version":1,"localLogoutComplete":true}
```

运行中的进程环境不能被外部强制改变。POSIX release 在各 shell 下一次正式刷新时恢复该 shell 自己的首次接管原值，工具新增项移除，无关变量保留；没有配置 hook 的 shell 需要显式刷新。源代码测试包含同一个真实 sh 的前后两次刷新。卸载导致整个固定状态范围消失时的终端恢复由独立 shell hook 机制负责，不能拿本命令输出当所有活跃进程已经刷新。

失败可能已持久关闭账号并清掉部分 slot，但恢复记录会保留到实际 provider 和最终保存成功。修复明确的本地冲突后，以相同目录重试；不会新建账号、重新配对、推进已经关闭的 epoch 或启动同步。安装器必须在命令结束后重新冻结/取得适用锁，确认全部当前账户 slot 缺失并拒绝并发新登录材料，不能仅相信 stdout 或文件名 allowlist。

验证入口：`mise run test-offline-local-logout`。本实现仍是实验性安全软件；没有执行真实安装器或系统服务卸载验收。
