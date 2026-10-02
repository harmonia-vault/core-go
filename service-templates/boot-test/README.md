# 隔离来宾的真实设备启动验收

本目录仅用于获准创建的独立 OrbStack Ubuntu 24.04 ARM64 测试机。全部账号、邮箱、恢复材料、设备钥匙、值与 TLS 证书都是本次合成测试；不读取宿主 env、钥匙或已有用户文件。不得对已有工作 VM 执行这些准备/重启/清理命令。

本轮实际结果保存在上级 `orbstack-boot-result.json`：原生 SPAKE2 上游 6/6、首次双签初始化、新设备双向确认入网、设备持钥 boot、签名共享写与验证 pull 均通过。删除本地登录 slot 与引导文件，清空服务器旧 session 后，正式 daemon 自动取得新设备 session。仅重启新来宾，再确认 init/两单元 InvocationID 改变、目标 UID 无登录 session、没有密码登录、新 boot/pull、当前用户 IPC/sh 与第二 UID 拒绝。

OrbStack 报告 LXC。namespace boot ID 变化，但共享内核 uptime 连续；这是来宾 init 重启证据，不能当物理内核启动、磁盘解锁或完整 Linux VM 验收。全局 LXC drop-in 关闭多项 systemd 沙盒，脚本不修改它。Windows/macOS 原生开机仍未跑；既有 UTM 只读状态为 started，guestexec/CUA 执行能力仍阻塞。

## 输入与执行顺序

脚本使用固定的本轮测试 UID 30001/30002；如名字、UID、目录或单元有冲突立即停止，不能覆盖。脚本只适用于 hostname 前缀 `harmonia-boot-test-`、没有 `/mnt/mac` 的专用新来宾，不自动创建/重启机器。Python 必须正常模式运行，不能使用 `-O`。

1. 在宿主用官方 `orbctl` 检查现有名称及磁盘后，以唯一名称创建新机：`orbctl create --isolated --isolate-network --user harmonialab --arch arm64 --cpus 2 --memory 2G --disk 8G ubuntu:24.04 <新的harmonia-boot-test-名称>`。确认配置不共享宿主 home、不转发 SSH agent。创建和机器重启必须在用户授权范围内通过正常工具审批。
2. 在 workspace 用 `python3 core-go/service-templates/boot-test/build-inputs.py --workspace "$PWD" --output /tmp/harmonia-boot-source.tar.gz` 打包。它先运行仓库公开源检查，只打包源码和本目录两个 `.in` 合成入口，不含忽略的构建产物、原生库、部署数据和私钥。
3. 仅新机 root 在 `/var/tmp/harmonia-boot-input` 建输入目录，传入 source tar，命名为 `source.tar.gz`，同时传入本目录 Python 脚本。执行 `install-test-tools.py`，官方 apt 工具依赖、Go 1.26.4/Node 24.16.0 tar 的官方 SHA256 核验、固定 pnpm 11.5.2 安装只发生于该新机；已有 `/opt/harmonia-test-tools` 则拒绝重复安装。不要改代理或系统安全配置。
4. 在新机创建 `/srv/harmonia-boot-src`，解包公开源，允许专用构建用户编译；用其非 root 身份安装 server 锁文件依赖并执行 `core-go/pairing/tools/build-native.sh`。该脚本固定 BoringSSL commit，运行真实 `SPAKE25519Test.*`。不要使用宿主 native 库或迁移宿主加密状态。
5. 执行 `prepare-fixture.py`。它解包同一输入到专用源目录，创建无密码/不可交互登录的两测试账号、只读显式 CA、回环 HTTPS/持久 SQLite 系统服务。服务复用 server 同一 `VaultService/nodeServer` 业务，不增加信任绕过路由；只记录 method/path/status，绝不记录 headers、正文或 token。WebSocket 不参与本次启动验证。
6. 在 source 根用 Go 1.26.4 编译：`go test -c -tags harmonia_boringssl -o /tmp/harmonia-native-boot.test ./acceptance`；在 `core-go` 编译：`go build -tags harmonia_boringssl -o /tmp/harmonia-native-boot ./cmd/harmonia`。将 CLI 安装到本次专用 root-owned `/usr/local/lib/harmonia-boot-test/harmonia`，模式 0755，不能让测试用户修改服务程序。
7. 执行 `runuser -u harmonia_boot_device -- env -i PATH=/usr/bin:/bin /tmp/harmonia-native-boot.test -test.run '^TestOrbStackBootPreparation$' -test.v`。钥匙在来宾目标 UID 内随机生成；正式首次初始化、原生配对、签名 grant/HPKE/AEAD 与共享写后，加密状态序号应为 3。本地登录 session 被删除，不迁移 host machine key。
8. 执行 `enable-device.py`。删除合成引导文件/服务器旧 session，enable 正式 daemon 单元。它使用 `--local-directory ... --local-user 30001 --ca-file ...`，正常 HTTPS 验证；不安装系统 CA、不关闭证书校验。执行 `probe.py before` 记录无登录、服务/审计基线。
9. 宿主仅执行 `orbctl restart <本次唯一测试机>`，再由新机 root 执行 `probe.py after`。只导出 `/var/lib/harmonia-test-server/public-result.json`。不得导出 account SQLite、加密 Vault、机器钥、TLS 私钥、登录材料或原始 bootstrap 输入。
10. 执行 `cleanup.py`：只停止/disable 本次两单元、确认目标 UID 无残留进程、删除本次账号及钥匙/SQLite/状态/测试二进制；工具链和公开源保留。正常 `orbctl stop <本次唯一测试机>`，不删除/重置它，也不停止旧 Ubuntu/UTM 或其他用户进程。

Go `.in` 被输入生成器放到 workspace `acceptance`，复用现有测试 helper；不会成为 core-go 默认测试包。它只做一次本来宾初始化准备，不模拟云授权。本地软件机器保护仍受已解锁磁盘、同 UID/root 和服务进程攻陷的风险约束，不能宣传生产可用。
