# 系统服务配置样例

这些配置由 `platform` 的可测试生成器生成，只使用虚构账号与路径。它们是待审查配置，不是安装器；不要直接在宿主机安装样例。真实设备信任、机器保护密钥及云端同步接入未完成，正常 daemon 会拒绝启动。`--fixture` 只用于隔离的合成数据测试，正式配置不能加入这个开关。

生成到一个**尚不存在**的目录：

```sh
go run service-templates/generate.go --output /tmp/harmonia-service-review
```

生成器拒绝覆盖既有目录或文件。macOS 使用按 UID 区分的 LaunchDaemon，Linux 使用按 UID 区分的 systemd 单元；Windows 输出虚拟服务身份与目标用户 SID 绑定的 JSON 清单，并提供 SCM 生命周期运行适配器，不安装服务或授予 ACL。

详细权限、开机前密钥存储权衡、shell 原值恢复与实际测试边界见 workspace 的 `docs/SERVICES.md`。此项目采用 MIT。
