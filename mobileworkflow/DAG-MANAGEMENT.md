# 已激活 DAG 设备的单环境授权管理

`DAGManagementDevices`、`PrepareDAGDeviceGrant`、`DAGManagementInfo`、`RetryDAGManagement` 和 `CancelDAGManagement` 只用于已经正式 Boot/P4Pull/最终 CAS 激活的本机 recovered DAG 来源。普通 `Management` 仍为 nil；全设备撤销、旧来源升级和 manager reanchor 不属于这五个方法。

用户明确选择环境、已验证归档目标设备、ro/rw/admin/none 和期限。成熟 producer 校验 current Admin、精确 Ed/X、当前 KV、最高 GG+1 与临时权限截止；原签域、Version2 包和服务端原 ID receipt 不变。新签包/随机 HPKE 只生成一次，prepare 先保存原包，不 POST。

fresh 完整管理目录必须在生成 HPKE 和 unknown 原包重交前通过同 owner/hash/epoch 的 whole-state CAS。全部已验目录和确认原 Packet/receipt 构成环境轮换共用的 GG/hash/seq 下界；none、过期、遗漏行不能清下界，同 GG 异 hash 拒绝。确认序号必须严格大于原控制基点，已确认但尚未 Applied 也约束随后发钥。只防已见历史回退，不证明隐藏后续权限或缺席。

业务 journal 保存原 protected transaction、contentHash、Attempted、接受 sequence、Applied、Canceled；最多 32 条，保留完整完成/取消历史，满额拒绝。它独立于恢复 checkedjournal，不存 bearer、恢复码或私钥。冷启动重新验证原来源、签包、历史目录和共享下界。取消仅限从未尝试的记录，永久退休原 ID；unknown 只能原 ID 查询/原包重试。

接受后通过成熟 receipt 与完整 P4 Pull 收敛，再保存最终 Applied。任一错误不得提前报告成功；最后 native CAS 成功和 postCheck 后才输出同来源已授权 view。自身降权例外仅精确 subject=self、admin_required 和已验 own role 非 Admin，终态失效优先传播。

本片 Go/native AES 合成测试不等于手机系统认证、SDK 或 Flutter 实测；平台和 verified 能力保持关闭直至各自实际验收。
