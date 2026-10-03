# 恢复来源设备的环境与权限控制

本批只接通 Go 同步客户端及真实联合业务链。手机高层的环境原包日志、原生桥和界面仍须明确接入相同新能力，不能以此声明所有平台管理入口已完成。软件仍是实验性实现。

## 明确能力与原信任来源

已受保护的第四版入网或恢复登记上下文选择 `issuer-recovery-v1`。`EnvironmentControl` 与 `ManagementControl` 分别读取 `/issuer-evidence` 和 `/grant-management`，查询明确包含环境与能力。同名 HTTP `issuerEvidence` 字段只按所选能力严格解码：恢复能力为 `cryptox.IssuerRecoveryProof`，旧能力仍为 `cryptox.IssuerProofV2`，没有解析失败后的回退。

本机 DTO 用独立 `IssuerRecoveryEvidence` 指针保存第三版图；受保护 journal 的字段是 `issuerRecoveryEvidence`，旧字段不承载它。验证使用原受保护 pin、完整原初始化/恢复链/双签设备归档，并对当前控制图核验已见恢复检查点和接受序号上界。返回的 `VerifiedControlEvidence` 只能查询已验历史授权、精确 target 和历史权源；不能用历史身份或恢复码持钥推导当前权限。

管理主体可以已被可信接受，却从未获得当前环境授权。第三版图的 `VerifiedIdentity` 验其原初始化或完整双签归档中的 Ed25519/X25519 绑定；不把裸 `subjects` 当可信目录，也不把只有权源节点的 `IssuerBindings` 误当完整身份集合。当前 grant（包括 none、到期和旧 KV）仍独立验签、最高 GG 精确匹配；null/GG0 不证明历史缺席，高层受保护已见下界不能因此降低。

所有发送前仍要求在线、本机当前 Admin、当前 KV/GG、有效期限和账号/设备代际。暂停拒绝控制写；历史 journal 重验不恢复已过期权力，重试发送会重新读取并核验当前控制图。

## 环境创建与轮换

- `PrepareEnvironmentChangeV3`：读取完整当前接收者控制图，要求原签包的预期序号与控制序号相同，再使用成熟的变更及来源签名原语生成两签包。
- `SubmitEnvironmentChangeV3`：只提交 `/environment-changes-v3`，成功后查询原幂等 ID 的精确内容摘要和尾序号，并经普通 `Pull` 验证原环境事件、来源图、全部内层写入和当前授权，才返回 `Applied=true`。
- `EnvironmentStatusV3` 与 `ConfirmEnvironmentChangeV3`：结果不明时恢复同一密封原包；不能按当前同名值或权限猜接受，不生成新 ID、nonce、密钥或接收者名单。

第三版路由沿用 `cryptox.EnvironmentChangeV2` 的 `{change,signature,origin}` 原包与原签名域、内容摘要及幂等库，并未重新发明签名编码。创建与轮换必须走明确能力路由；恢复客户端拒绝旧的 V2 操作入口。轮换仍保留全部合法接收者、角色与期限，增加新 KV/GG、重新封装独立环境钥、重新加密全部当前值，并生成恢复封套。服务端按同一事务检查接收者闭包、精确原序号及原权限，客户端不会提前修改本机权威状态。

重命名、删除、既有设备授权更新和全局撤销继续使用原签名域与路由。`PrepareGrantUpdate`、`RestoreGrantUpdate` 及 `PrepareOtherRevocation`、`RestoreOtherRevocation` 复用原密封交易机制，控制证明按明确能力保存。全局撤销保存的原短时会话绑定不会改成新 token/hash；后续状态查询可使用新持钥会话，原包不能自动重签。

## 实际验证

`workspace/acceptance/recovery_control_test.go` 使用真实注册/初始化、手机高层连续恢复、TypeScript/SQLite HTTPS 服务、BoringSSL 原生 SPAKE2 及实际 Ed25519/HPKE/AEAD，已完成：恢复 E 创建 Z；接受响应丢失后按原包/hash 确认且无新 POST；真实配对 F 读写；轮换后全部接收者与当前值保留；F 用新 KV 继续写；RO 降权后的写入拒绝；none 下发清缓存；全局撤设备后新持钥启动拒绝并持久关闭账号。完整定向 race 通过（15.72 秒）。

同步包的独立合成 DTO/journal 测试验证原能力选择、受保护交易恢复、旧 profile/恢复链回退、主体公钥与最高 GG 篡改拒绝；它不替代上述真实服务接受语义。所有测试只使用合成账号、凭据和值，不扫描宿主环境、不安装服务。
