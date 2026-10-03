# 本机离线退出验证

最终源码基线为公开 core-go `9b3f5fa36986a03eb0d579289b8cc00d5c33ad5e`，包含既有 POSIX 完整范围消失恢复切片。本候选仅独立归档，不修改活跃仓库、Windows 未提交工作、宿主服务或 VM。

| 项目 | 结果 | 范围 |
| --- | --- | --- |
| cmd/harmonia、localkeys、platform 三包 race | PASS，163/163，0 fail，0 skip | 总耗时 9.172 秒；包含新增 30 项和既有回归，不代表 163 次安装 |
| 三包 go vet | PASS | 5.065 秒 |
| Darwin arm64 CLI 构建 | PASS | Go 1.26.4，CGO_ENABLED=1，实际 Mach-O；5.228 秒 |
| 新安装器/真实 VM 卸载 | UNRUN | 未安装、未执行该命令于用户真实目录 |
| Linux 原生本轮运行 | UNRUN | 共享 Unix 源码未以 Mac 结果冒充 Linux 系统验收 |

产物 11320898 字节，SHA256 `83d49b5f6f5918b43f0725f5dba8a797cef6333479e61513d568f14b8893d523`。仅本地编译，没有打包或发布；此默认构建没有另行开启原生 PAKE 标签，不能据此宣称完整配对链已验证。

新增测试在当前普通 Unix UID 的临时目录使用真实加密 Vault：所有 account slot（含 recovery-dag-v1）删除、AccountClosed 和 epoch 持久、已关闭最大 epoch 重试、provider 写失败与最终 Save 失败保留恢复记录后幂等完成、原值逐 key 恢复与无关项保护；同一个真实 sh 先消费合成配置再消费 release。HTTP 客户端计数为零，命令未创建 IPC 目录。运行中的正式合成 idle daemon 持有真实 Vault 时，离线入口以 ErrBusy 拒绝，原 owner 继续可用；此测试后台是故障夹具，不是离线命令创建的后台。

existing-only 回归包括目录/锁/机器钥缺失无重建、真实独占锁、宽 mode、硬链接、symlink 与错误身份的拒绝。provider 全 I/O spy 验证关闭重试在加载、Apply 与 Finalize 的任一写阶段都不出现旧值，最终 release 输出幂等；spy 只验证流程，不是密码学或真实文件保护通过证据。另有实际加密 provider 的未追踪 Desired 回归，拒绝前 fragment 字节保持不变、不输出完成。

第一轮公开 06db7bb 基线的新增定向回归 27/27 PASS、0 skip（9.794 秒），原源码与日志保留；后续加入三项和已公开 POSIX 更新，再验证最终完整基线。

最终三包第一次在沙箱运行实际 FAIL：116 项通过，既有 IPC 启动错误后，httptest 明确报本机 IPv6 loopback bind 的 operation not permitted。该原日志保留，不改报 PASS。正常工具审批允许本任务合成 loopback/Unix socket 后，以相同源码和受限的明确测试环境复跑，得到上述 163/163 PASS；未改变宿主安全权限、代理或真实 env。

现有 daemon、正常 provider 加载行为及账户 slot 清理枚举未另造实现；POSIX RenderShellHook 与公开 9b3f5fa 保持逐字不变，仅 provider 私有 I/O 字段用于行为轨迹测试。Mac 安装器 v4、v5 持久清理事务、当前在线授权和只读入网检查均不在本切片通过范围。
