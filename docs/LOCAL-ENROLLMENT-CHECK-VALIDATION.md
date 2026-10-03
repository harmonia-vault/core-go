# 只读本机入网检查验证记录

本切片基于公开源码 `18a72fa4adea5adec69fb774e25e0d045d3c50b5`，在独立归档中实现和验证，没有改写活跃 Windows 工作树、安装系统服务或读取真实账号材料。

| 验证 | 真实结果 |
| --- | --- |
| `go test -race -count=1 -json ./cmd/harmonia ./localkeys ./platform` | 217 个测试事件 PASS，0 FAIL，0 SKIP，26.523 秒；其中新入网检查 54 个测试事件 PASS |
| `go vet ./cmd/harmonia ./localkeys ./platform` | PASS，0.820 秒 |
| `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath ./cmd/harmonia` | PASS，0.926 秒；生成 Mach-O arm64 CLI，11,321,682 字节 |

CLI SHA256：`6058253319e17ff1ce1e7f489fa9fe693d34906f36d723d8525bacccd0c8720a`。该构建没有原生 BoringSSL 配对功能，不能作为新的 PAKE 验收；既有完成入网收据的签名检查使用正式纯 Go 验证逻辑。

新增回归实际加载公开 v3、v4、v5 已签证书对应的 Ed25519/X25519 合成钥匙，并通过成熟 `verifiedStoredContext` 核验。另由成熟 `VerifyPull` 产生完整已签来源账本，保存后重新打开真实临时加密 Vault 检查，不能用一个 `Accepted` 标记或手写成功 DTO 替代密码学通过。

拒绝路径覆盖：待完成入网、坏管理签名、错误账号代际/设备、未知版本、`AccountClosed`、缺失/损坏必需账本、缺目录/机器钥/锁/设备或信任材料、真实 owner 持有 Vault 锁、非法路径/UID、额外服务/CA/fixture/导入参数、取消，以及真实存储释放后注入的 `Close` 失败。关闭故障与核验故障同时发生时，两者都保留，标准输出没有成功结果。

测试前后核对整个 Vault 的文件集合、字节摘要、inode、mode、size 与 mtime，没有改变。读取可能影响文件系统 atime，因此不将 atime 当写入证据。观察 Store 的 `Save` 调用为零，注入 HTTP transport 的调用为零；命令没有构造同步 worker、平台 provider 或 daemon。取消/关闭失败后重新打开 Vault 成功，确认该流程释放了独占锁。

这些结果仅支持本地已有材料可核验。Linux 原生执行、Windows、新服务安装器接线、VM 启动、当前服务器授权，以及新设备 PAKE 流程在本切片均未运行。旧版本证书仍复用现有正式分支，其既有回归包含在联合检查中；新增签名向量主要覆盖 v3–v5。软件仍处于实验阶段。
