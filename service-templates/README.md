# 系统服务配置样例

这些配置由 `platform` 的可测试生成器生成，只使用虚构账号与路径。它们是待审查配置，不是安装器；不要直接在宿主机安装样例。正式 POSIX daemon 已接加密状态、原生配对信任上下文及持钥 boot/sync；生成器和样例现使用正式 `--local-directory <UID 隔离目录>` 与 `--local-user` 接口；`environment.sh` 固定在加密 Vault 目录内。自托管 CA 可通过 `ServiceConfig.CAFile` 显式生成 `--ca-file`，保留正常 HTTPS 主机名/链验证，不安装系统 CA。Windows 正式 daemon 和三平台原生开机验收仍有门槛。`--fixture` 只用于隔离的合成数据测试，正式配置不能加入这个开关。

生成到一个**尚不存在**的目录：

```sh
go run service-templates/generate.go --output /tmp/harmonia-service-review
```

生成器拒绝覆盖既有目录或文件。macOS 使用按 UID 区分的 LaunchDaemon，Linux 使用按 UID 区分的 systemd 单元；Windows 输出虚拟服务身份与目标用户 SID 绑定的 JSON 清单；清单明确正式 daemon 仍关闭，不能拿编译通过当原生可运行。生成器不安装服务或授予 ACL。

详细权限、开机前密钥存储权衡、shell 原值恢复与实际测试边界见 workspace 的 `docs/SERVICES.md`。此项目采用 MIT。

## OrbStack Ubuntu 隔离验收

`verify-orbstack-fixture.py` 必须在已获授权的 OrbStack Linux 机内以 root 运行，并显式允许新建临时 fixture 账号。依赖官方 Python、systemd、OpenSSH、acl 和账户管理工具；不自动安装依赖。先构建对应架构的 CLI 与 Go 测试二进制，再在隔离机运行：

```sh
python3 service-templates/verify-orbstack-fixture.py \
  --allow-temporary-fixture-account \
  --binary /tmp/harmonia \
  --localkeys-test /tmp/localkeys.test \
  --platform-test /tmp/platform.test
```

脚本只创建随机命名临时账号、单元、目录和全新合成 SSH 密钥，专用 sshd 仅监听 `127.0.0.1`、关闭密码/代理/端口转发。通过当前测试用户 CLI 检查激活排序、override、暂停、服务重启、到期与逐 key 退出恢复；第二 UID 必须被拒绝。它不读取真实环境或已有用户文件，不重启整机，不变更全局 systemd 安全配置，也不启动默认 SSH 服务；只清理本次创建的资源。

`orbstack-fixture-result.json` 保存本轮脱敏结果。OrbStack Ubuntu 当前检测为 LXC，系统全局 drop-in 关闭多项 systemd 沙盒，因此这些沙盒的生效验证仍待完整 Linux VM。实际 service start 只证明无人交互操作的启动，不能替代整机开机或真实设备授权验收。

## 真实入网后的来宾 init 重启

`boot-test/README.md` 与对应脚本保存另建隔离来宾的真实原生 SPAKE2→双签入网→设备 boot→签名写入→init 重启验收。`orbstack-boot-result.json` 逐项记录通过与未跑门槛；合成账号的权威数据由真实 Node/SQLite 业务维护，正式加密 Vault 的钥匙在该来宾目标 UID 生成，未迁移宿主钥匙。测试机工具链保留并停机，账号、单元和敏感测试数据清理后不再有可继续同步的设备状态。LXC init 重启不能代替物理内核启动或全 systemd 沙盒证明。
