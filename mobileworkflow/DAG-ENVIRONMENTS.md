# 已应用 DAG 来源的环境操作（实验性）

本入口只接受 B3b 已正式 Boot、P4 Pull、最终 whole-state CAS 的本机登记来源。
普通环境入口、P2/P3 parser、恢复 checked journal 均不扩展。尚未验证的手机
compiled/verified 能力保持关闭；Go 临时 AES store 不能证明系统认证、SDK 或 UI 可用。

`CreateDAGEnvironment` 必须由用户明确选中 `authorityEnvironmentId`，不自动选择
第一个 Admin。create/rename 名称通过独立内存缓冲输入，trim 后非空、合法 UTF-8、
不含 NUL、最多 120 Unicode 字符。rename/delete/rotate 明确指定目标环境。
每次业务重新 Boot 和完整 P4 Pull；暂停、失权、到期、原账号/代际不符时硬拒绝。

业务 journal 单独绑定 account、generation、device、原登记 ID/hash；每个随机环境 ID、
AEAD/HPKE 封套、签名、origin、原输入 fingerprint 只生成一次。最多 32 个原操作、
32 份完整管理证据和整体 8 MiB，预算不足不驱逐历史。它不是 recovery-dag-v1
RecoveryTransition/DeviceEnrollment checked journal。原包先 native CAS，再在线 POST。
响应未知保留原 ID；重启后只按原包查询或重试，不用当前同名值猜接受。确认原收据、
全量验证下发、原包 checkpoint 和最终 native CAS 全成功才返回 Applied 与授权 View。

create/rotate 使用明确 P4 控制及 `/environment-changes-v4`，强制 major 2/capability。
rename/delete 保留成熟 change 签名域和 raw route 的旧 header 兼容语义；本 P4 客户端
仍显式请求 major 2，并通过完整当前 DAG 验证，不隐式 fallback。

轮换生成任何新 HPKE 前，另取成熟 `ManagementControl` 完整已验 current rows。
环境控制与管理控制必须同 seq/KV，所有有效 receiver 逐完整签包完全相同；none、
到期、旧 KV、遗漏 subject 不得获得新 key。所有有效受件人角色和精确期限保留，
每个 GG 加一、KV 加一，包含当前恢复受件人和全部 live 值的新密文。

已验证管理 snapshot 先通过同 owner/hash/epoch whole-CAS 保存，再做 receiver 比较。
即使后来 mismatch 或 prepare 失败，也不能遗忘已见更高 GG/none。冷启动逐份完整
证据复验原 pin、双钥身份、历史签权，推导最高 GG/同 GG 完整签包 hash 下界；后续
遗漏、过期、null 不清下界。未知原轮换再 POST 前使用同一 current 管理门，原 before
也必须精确匹配。历史 `true` 只用于密封包重验，不授当前权限。完全空 journal 拒绝；
仅有完整受验 history、尚无原操作的 journal 合法，pending 返回空列表。

该机制保护已见授权下界，不提供“从未见过的撤销不存在”或密码学完整 absence 证明。
服务端尚未展示的后续授权无法凭当前 snapshot 排除，服务端仍逐次事务校验当前权限。
保存/预算失败只在 native 仍确认精确 captured 旧保护版本时发出清理标记；槽已推进或
检查未知仅退休旧 handle，不删除新账号/新版本。复用已公开 verified-Pull 提交和取消
安全投影；没有乐观本地改值，不用一般 epoch 变化推断全局撤销。

独立 Go bridge 为 `ValidateDAGEnvironmentCommand`、`DAGEnvironmentProfile`、
`VaultWorkflow.ExecuteDAGEnvironment(command, nameBytes)`。六个操作为
`createDAGEnvironment`、`renameDAGEnvironment`、`rotateDAGEnvironment`、
`deleteDAGEnvironment`、`pendingDAGEnvironments`、`retryDAGEnvironment`。
命令严格 4096 UTF-8 bytes、version=1、canonical HTTPS endpoint，ID 最多 64 ASCII
字符（`[A-Za-z0-9][A-Za-z0-9._:-]*`）。nameBytes 最多 480 bytes，只有 create/rename
可非空。Go 消费后清该缓冲；不接受 argv、日志、调用者公钥、封套或签包。

原操作 metadata 固定 `{requestId,operation,environmentId,sequence,applied}`：
sequence 为规范十进制字符串，未知为 `"0"`，Applied 要求正接受序号。成功只返回
同来源已授权 FullView；pending/unknown 为 false trust/no View。原 ID 冲突或硬权限、
来源、CAS 错误不伪造 soft success。每环境 RO/RW/Admin/期限与撤销入口、全设备撤销、
manager reanchor 仍需后续来源专用接线，不能以本六操作宣称 P1 产品完整。
