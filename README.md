# Harmonia / 和弦：Go 核心与 CLI

本仓库实现环境密文、设备签名、本机合并与恢复、HTTPS 同步客户端及三平台 CLI。采用 MIT 许可证。当前是实验性实现，安全与系统集成尚未完整验收，不能用于生产凭据。

完整目标与执行计划见 [workspace 设计](https://github.com/harmonia-vault/workspace/blob/main/docs/DESIGN.md) 和 [里程碑](https://github.com/harmonia-vault/workspace/blob/main/docs/PLAN.md)。协议字段和签名字节见 [protocol](https://github.com/harmonia-vault/protocol)。

## 已实现的技术职责

- `cryptox`：成熟库 XChaCha20-Poly1305、标准 HPKE、Ed25519 签名、恢复用途派生与确定性协议编码，详见[密码学说明](cryptox/README.md)。
- `localstate`：设备自己的激活优先级；先替换环境内 override，再跨环境合并；首次接管按变量记录原值；删除、停用、撤销或到期后重新计算其它来源，最后恢复原值或移除新增项；无关项保留。
- 本地授权到期、已收到的撤销和退出账号会立即删除相关缓存明文。即使 provider 暂时失败也保存清理后的缓存与待恢复名字；正常崩溃不会清空全部配置，重新启动可幂等收敛。
- 暂停阻止普通同步与纠正；已知撤销和到期仍恢复或下发剩余来源。POSIX shell provider 使用每个 shell 的原值，暂停时只应用新的安全修订一次。
- `syncclient`：HTTPS、禁止重定向携带会话、账号/代际/设备绑定、设备持钥挑战与绑定会话、持久化序号拉取。已批准设备可用 `NewForBoot` / `BootDevice` 重建包含本机双公钥的挑战，获得设备会话；不保存或重发密码派生凭据。提交成功后必须经过验签拉取再更新本机，不会乐观更新。网络结果不明时保留幂等键和接受序号。
- `PinnedVerifier`：v1 固定可信管理公钥，v2 从受保护双签回执重验逐环境签发来源；逐项绑定本机签名/接收公钥；验管理签授权与作者 RW/Admin 签授权、设备签名、环境版本、AEAD；保存授权最高代际和已见变更的原序号/摘要。新环境或 key version 获权后自动全量补拉，防止全局序号漏掉原有变量。
- `localipc`：后台独占 Engine / Store，当前用户 CLI 经原生身份校验发送激活、优先级、override、暂停、退出、状态与导出命令；多个命令与后台纠正共用串行锁。接口不接受云快照、设备钥匙或信任资料，详见[本地通信](localipc/README.md)。
- `localkeys`：独立机器软件钥和 XChaCha20-Poly1305 加密状态，按 UID/SID 隔离并独占；受保护 Store 与 IPC 的退出失败、重启恢复已有合成联动测试，详见[机器保护](localkeys/README.md)。
- 本地账号 session epoch 持久化；退出账号先使旧请求失效并清云缓存，迟到拉取不能重新写回。后台退出回调负责停止旧同步并删除设备/session slot，原值保留到恢复成功。
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

`status` 仅输出元数据；`export` 明确输出可 source 的有效变量；`exec -- <程序>` 将有效值传给新建子进程；它们不能外部修改已存在进程。`import-preview --from <候选JSON> --select A,B` 只选择明确勾选的项，不扫描宿主环境，也不提交云端。共享写入 `put/delete/import` 只能经受保护后台在线提交；`login/pair` 只能使用下述受保护目录，不能使用 fixture。

`--platform-fragment <绝对路径>` 可在隔离目录验证真实 shell fragment，`shell-hook --shell bash --platform-fragment <绝对路径>` 仅生成供审查的 hook 文本。请勿把演示接到真实凭据或宿主 shell。

## 后台与当前用户 CLI

仍使用上述明确的合成状态与隔离 provider。在第一个终端启动后台，随后可以在其它终端运行白名单命令；这些 CLI 不打开状态文件，因此不会与后台的独占锁冲突。IPC 目录须归当前非 root 用户所有、权限为 `0700`。macOS / Linux 示例：

```sh
mise exec -- go run ./cmd/harmonia daemon --fixture \
  --state test-state/state.json --provider-file test-state/environment.json \
  --ipc-dir "$PWD/test-state/ipc" --interval 2s

# 另一个终端运行；关闭该 CLI 不会关闭后台。
mise exec -- go run ./cmd/harmonia activate --fixture \
  --ipc-dir "$PWD/test-state/ipc" --environment dev --priority 10
mise exec -- go run ./cmd/harmonia override-set --fixture \
  --ipc-dir "$PWD/test-state/ipc" --environment dev --name TOKEN --value synthetic-local
mise exec -- go run ./cmd/harmonia pause --fixture --ipc-dir "$PWD/test-state/ipc"
mise exec -- go run ./cmd/harmonia status --fixture --ipc-dir "$PWD/test-state/ipc"
mise exec -- go run ./cmd/harmonia resume --fixture --ipc-dir "$PWD/test-state/ipc"
mise exec -- go run ./cmd/harmonia logout --fixture --ipc-dir "$PWD/test-state/ipc"
```

`logout` 清账号缓存、恢复托管项，后台继续等待命令。停止或崩溃不会清空全部配置；重启后台会从同一状态收敛。暂停保配置，已收到的撤销和本地期限到期仍执行。IPC `exec` 仅覆盖新进程当前有效值；已存在 shell 的原值恢复和纠正由已审查的 shell hook 执行。

明文 fixture 不迁移到 `localkeys` 的加密 Store，上述演示不授予网络信任。Windows named pipe 候选须指定目标 SID 和服务 SID，原生运行验收前不作为安装指引。

## 受保护入网与后台同步

macOS / Linux 的实验入口使用 `--local-directory <绝对规范路径>`；父目录须已存在且没有任何符号链接，最后一级由工具创建为当前普通用户的 `0700` 私有目录。机器软件钥、设备钥匙、入网收据、状态和 provider 元数据受本机 ACL/文件权限及 AEAD 保护；shell 必需的 `environment.sh` 为固定路径的本地 `0600` 明文片段。持钥机器服务不能依赖登录后才能解锁的 Keychain；本实现依赖磁盘保护和本地用户隔离，不能声称软件钥始终在硬件中。磁盘尚未解锁时服务不能启动。

首次入网须已有可信管理手机，CLI 没有首台管理设备初始化旁路。先停止占有该目录的 daemon，再登录和配对；登录仅保存随机短期会话，不保存密码或 SHA256 密码等价凭据。交互密码不回显，管道输入必须明确 `--password-stdin`。Go 运行时中的历史内存副本不能保证全部抹除。

```sh
# SERVER 和 LOCAL_DIR 为明确选择的 HTTPS 地址、当前用户私有规范路径。
mise exec -- go run ./cmd/harmonia login --local-directory "$LOCAL_DIR" \
  --server "$SERVER" --email synthetic@example.invalid
# 原生库构建说明见 pairing/README.md；默认构建的 pair 会关闭并报错。
mise exec -- go run -tags harmonia_boringssl ./cmd/harmonia pair \
  --local-directory "$LOCAL_DIR" --approver trusted-manager-device-id
mise exec -- go run ./cmd/harmonia daemon --local-directory "$LOCAL_DIR" \
  --interval 2s --sync-interval 15s
# 其它终端的当前用户 CLI 经同一受保护目录/ipc 连接后台。
mise exec -- go run ./cmd/harmonia activate --local-directory "$LOCAL_DIR" \
  --environment environment-id --priority 10
mise exec -- go run ./cmd/harmonia pause --local-directory "$LOCAL_DIR"
mise exec -- go run ./cmd/harmonia resume --local-directory "$LOCAL_DIR"
mise exec -- go run ./cmd/harmonia logout --local-directory "$LOCAL_DIR"
```

新 `pair` 使用独立 `/pairings-v2`，双方明确支持 `issuer-proof-v1`；既有 v1 pending 保持原证书恢复。v2 不保存全局 Managers，完整证明与双签回执被冻结，后台重开从本机精确双公钥重验；不会静默降级。本机产生八位短码并显示，手机输入该码，短码不交服务器。只有成熟 SPAKE2 双向确认、管理公钥绑定、签授权与 HPKE 验证通过后才保存待完成双签收据；提交结果不明时再次 `pair` 查询同一收据，不新建授权。服务器确认完成后才记录 accepted 状态。默认构建不包含原生 SPAKE2，配对入口保持关闭；已有受保护且验签通过的完整入网资料可供普通构建启动后台。

后台独占加密 Store，重启只用设备 Ed25519 持钥挑战换取绑定会话。未入网或仍 pending 的后台只提供本地状态和恢复，不连接网络。暂停时仅刷新授权和签名环境生命周期，保持普通值及数据序号；授权序号可以领先，恢复时从零重建当前可读历史。删除、降权、撤销及到期仍执行；轮换密文清单仅作为生命周期签名证明，不在暂停时下发变量。普通会话到期会立即重做设备挑战；设备不可信或账号 generation 失效时清账号材料并恢复托管项，所有环境授权失效时清值缓存但保留既有可信设备以便日后重新获权。

退出 CLI 不停止后台；退出账号等待旧同步停止并删除设备、会话、信任资料，后台仍可应答。停止后台/崩溃保留配置。登录和配对目前必须在 daemon 停止时执行，手机管理界面和自动服务安装尚未接入。Windows 正式受保护 daemon 在原生 DPAPI、服务 SID、SCM 验收前明确关闭。这里的命令说明用于合成自托管测试，不代表安全功能已完整或适合生产凭据。

## 显式共享写入

共享 `put/delete/import` 与本机 override 是独立命令。受保护的值只从标准输入进入，拒绝 `--value` 参数；空值和换行按输入原样保留。每值最多 64 KiB，导入一次最多 16 个选中变量、选中值合计 64 KiB。候选 JSON 标准输入最多 1 MiB；未选中的项不会进入 IPC 或云端。当前尚未实现本机会话环境扫描，候选须由用户主动准备；daemon 不采集宿主 env。

```sh
# value.txt、candidates.json 只含私有合成测试数据，不把值放到argv。
mise exec -- go run ./cmd/harmonia put --local-directory "$LOCAL_DIR" \
  --environment environment-id --name TOKEN --value-stdin < value.txt
mise exec -- go run ./cmd/harmonia delete --local-directory "$LOCAL_DIR" \
  --environment environment-id --name TOKEN
mise exec -- go run ./cmd/harmonia import --local-directory "$LOCAL_DIR" \
  --environment environment-id --import-stdin --select TOKEN,URL < candidates.json
mise exec -- go run ./cmd/harmonia override-set --local-directory "$LOCAL_DIR" \
  --environment environment-id --name TOKEN --value-stdin < local-value.txt
```

后台串行预拉当前签授权，确认 RW/Admin、到期和环境版本，再用本机钥匙解封环境钥、随机 AEAD 加密并签名。提交前，`writes-v1` 以机器保护保存原签名密文和请求 ID；没有原始值。服务端仍逐次检查权限，LWW 按服务器接受顺序；协议没有变量 CAS 或 `expectedSequence`，本机预拉序号仅记录提交基线。暂停时拒绝共享写入，离线不会把输入应用到本机。

CLI 在请求前输出非秘密的请求 ID，结果仅含总项数、接受项数、接受序号和是否完成验签下发。结果不明时运行 `write-retry --local-directory "$LOCAL_DIR" --request-id <原ID>`，不重新输入值。它先按本设备幂等 ID 查询精确接受回执的内容摘要与原序号，再用原密文/签名重试未接受项；不通过当前同名值猜成功，不换 nonce 或新 ID。重启保留同一日志。被后来写入覆盖时，精确已见签名及原序号仍可证明接受；当前可读同版本缺少该验签项时不宣称下发完成。轮换、降权或失权会取消旧待提交包并清密文，只保留有界 ID/摘要回执资料用于安全查询。

导入是多个独立 LWW 写入，可能部分成功；日志保留各项结果，同一请求重试不会重写已接受项。只保留最近最多 32 个请求；未解决项不会被自动驱逐，日志或持久化失败时拒绝发出新写。已接受后失权，接受记录不意味着值还能在本机生效。退出、全局设备撤销和账号代际失效清 `writes-v1`；持久账号关闭墓碑让崩溃重启继续清旧材料，不能复活旧入网授权。

自托管私有 CA 可以显式指定 `--ca-file <PEM证书>`，文件最多 1 MiB，追加系统根池并保留完整证书链、主机名和期限校验，不关闭 TLS 验证。系统信任设置不被修改。

后台已接单次票据 WSS 通知、退避重连及持久拉取补漏。暂停在途普通回应原子拒绝数据，仅验授权投影；正常取消不会吞真实持久化失败。详情见 [通知说明](NOTIFICATIONS.md)。

## 验证

- `mise run test`：全部 Go 测试，包括密码学互操作、权限验证、HTTPS、本机恢复及 shell/假注册表行为。
- `mise run test-race`：Go race detector。
- `mise run cross-compile`：构建 macOS arm64、Linux amd64、Windows amd64 CLI 到忽略目录 `.build`；编译通过不等于实际服务验收。

测试仅使用合成账号、随机临时钥匙、独立临时状态、TLS 测试服务器和假注册表。真实通过/失败/未跑结果由 workspace 状态文档记录。

## 尚未完成的入口与安全门槛

成熟原生 SPAKE2 的入网库与受保护 CLI/后台已有合成 TLS、加密状态及真实 Go/TypeScript/SQLite 集成验证；手机平台钥匙保护、手机端接线、Android Go 桥、三平台无人登录启动仍有验收门槛。fixture daemon 仅用于隔离服务通信验收。

本机 fixture 状态包含明文缓存，私有文件权限不能替代服务机器保护层。Windows ACL、profile/hive 生命周期与 Session 0 交互广播仍需真实 VM 验证。硬盘解锁前服务无法启动，已有进程读过的明文无法追回。

管理公钥来自本机 PAKE 确认及受保护双签回执，服务器目录不能建立信任。v2 已覆盖同环境、同 keyVersion 的根→B Admin→C 签发来源和归档 v2 路径；只输出逐环境历史来源，不恢复当前管理权或提升恢复公钥信任。非根新环境及跨 keyVersion 来源缺少签名生命周期扩展时仍拒绝。客户端不能独立证明服务器接受旧写入时尚未超过作者期限。签名、最高检查点和已见序号处理基本回放，不构成外部见证；完整手机批准、恢复和生命周期门槛仍在推进。
