# Harmonia / 和弦：Go 核心与 CLI

本仓库实现环境密文、设备签名、本机合并与恢复、HTTPS 同步客户端及三平台 CLI。采用 MIT 许可证。当前是实验性实现，安全与系统集成尚未完整验收，不能用于生产凭据。

完整目标与执行计划见 [workspace 设计](https://github.com/harmonia-vault/workspace/blob/main/docs/DESIGN.md) 和 [里程碑](https://github.com/harmonia-vault/workspace/blob/main/docs/PLAN.md)。协议字段和签名字节见 [protocol](https://github.com/harmonia-vault/protocol)。

## 已实现的技术职责

- `cryptox`：成熟库 XChaCha20-Poly1305、标准 HPKE、Ed25519 签名、恢复用途派生与确定性协议编码，详见[密码学说明](cryptox/README.md)。
- `localstate`：设备自己的激活优先级；先替换环境内 override，再跨环境合并；首次接管按变量记录原值；删除、停用、撤销或到期后重新计算其它来源，最后恢复原值或移除新增项；无关项保留。
- 本地授权到期、已收到的撤销和退出账号会立即删除相关缓存明文。即使 provider 暂时失败也保存清理后的缓存与待恢复名字；正常崩溃不会清空全部配置，重新启动可幂等收敛。
- 暂停阻止普通同步与纠正；已知撤销和到期仍恢复或下发剩余来源。POSIX shell provider 使用每个 shell 的原值，暂停时只应用新的安全修订一次。
- `syncclient`：HTTPS、禁止重定向携带会话、账号/代际/设备绑定、设备持钥挑战与绑定会话、持久化序号拉取。提交成功后必须经过验签拉取再更新本机，不会乐观更新。网络结果不明时保留幂等键和接受序号。
- `PinnedVerifier`：固定可信管理公钥，逐项绑定本机签名/接收公钥；验管理签授权与作者 RW/Admin 签授权、设备签名、环境版本、AEAD；保存授权最高代际和已见变更的原序号/摘要。新环境或 key version 获权后自动全量补拉，防止全局序号漏掉原有变量。
- `platform`：私有原子 shell fragment、sh/bash/zsh hook、按明确 SID 的 Windows 注册表适配、待审查的系统服务配置，详见[平台限制](service-templates/README.md)。CLI 不会自动修改 shell 启动文件或安装服务。

## 隔离 CLI 演示

安装并信任仓库指定的 mise 工具后运行 `mise run test`。CLI 必须明确给出状态文件；示例的状态目录应由当前用户以 `0700` 权限创建，状态文件及本地 fixture 环境以 `0600` 保存。

仅有 `fixture-load --fixture` 可加载未签名合成 snapshot，而且会永久标记该状态为测试来源。网络客户端拒绝这种状态，测试入口不能替代可信设备入网。

```sh
# 先准备只有合成值的 cloud.json 和 environment.json，以及私有目录 test-state。
mise exec -- go run ./cmd/harmonia fixture-load --fixture \
  --state test-state/state.json --input cloud.json
mise exec -- go run ./cmd/harmonia activate --fixture \
  --state test-state/state.json --environment dev --priority 10 \
  --provider-file test-state/environment.json
mise exec -- go run ./cmd/harmonia override-set --fixture \
  --state test-state/state.json --environment dev --name TOKEN --value synthetic-local \
  --provider-file test-state/environment.json
mise exec -- go run ./cmd/harmonia daemon --fixture --once \
  --state test-state/state.json --provider-file test-state/environment.json
mise exec -- go run ./cmd/harmonia status --fixture --state test-state/state.json
mise exec -- go run ./cmd/harmonia logout --fixture \
  --state test-state/state.json --provider-file test-state/environment.json
```

`status` 仅输出元数据；`export` 明确输出可 source 的有效变量；`exec -- <程序>` 将有效值传给新建子进程；它们不能外部修改已存在进程。`import-preview --from <候选JSON> --select A,B` 只选择明确勾选的项，不扫描宿主环境，也不提交云端。真实 `put/delete/import/login/pair` 命令保持关闭，直至设备入网及本机保护完成。

`--platform-fragment <绝对路径>` 可在隔离目录验证真实 shell fragment，`shell-hook --shell bash --platform-fragment <绝对路径>` 仅生成供审查的 hook 文本。请勿把演示接到真实凭据或宿主 shell。

## 验证

- `mise run test`：全部 Go 测试，包括密码学互操作、权限验证、HTTPS、本机恢复及 shell/假注册表行为。
- `mise run test-race`：Go race detector。
- `mise run cross-compile`：构建 macOS arm64、Linux amd64、Windows amd64 CLI 到忽略目录 `.build`；编译通过不等于实际服务验收。

测试仅使用合成账号、随机临时钥匙、独立临时状态、TLS 测试服务器和假注册表。真实通过/失败/未跑结果由 workspace 状态文档记录。

## 尚未完成的入口与安全门槛

正式 SPAKE2 手机确认入网、手机平台钥匙保护、服务机器保护与本地 IPC、Android Go 桥、真实三平台无人登录启动验收尚未完成。正式 daemon 因此关闭；目前 fixture daemon 持独占状态锁，不能当作已完成的 CLI/系统服务通信方案。

本机 fixture 状态包含明文缓存，私有文件权限不能替代服务机器保护层。Windows ACL、profile/hive 生命周期与 Session 0 交互广播仍需真实 VM 验证。硬盘解锁前服务无法启动，已有进程读过的明文无法追回。

管理公钥固定来自未来受信手机/恢复上下文；当前没有自动信任服务器公钥的入口。历史事件冻结作者签授权，但尚无完整的“签授权时 issuer 是 Admin”历史链；客户端不能独立证明服务器接受旧写入时尚未超过作者期限。签名检查、最高检查点和已见序号处理基本回放，不构成外部见证。撤销设备不等于已经完整实现环境钥匙轮换。恢复与账号生命周期需与服务端后续里程碑共同完成。
