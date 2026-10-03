# DAG 登录账号范围的原生 CAS 入口

`LoginDAGAccountScope` 仅接受 fresh 未可信、无业务/恢复 pending 的原生 Workflow。正常 SHA256 登录后，只保存精确账号/代际和原本机字段，已存账号/代际只能相同，不能因服务器回应替换；不保存登录 token、密码/派生值、受限 session、恢复码或 seed。

必须提供 CheckProtectedState 与 SaveProtectedStateCAS，当前完整状态 hash 检查和 CAS 成功后高层自身推进 protectedSHA256；桥不得 Export 后自行 save 或补 hash。CAS/check 失败关闭此 Workflow 并清设备钥，不进入恢复网络。SessionEpoch0 为合法新本机范围。

桥顺序调用 `LoginDAGAccountScope(ctx,email,password) (DAGAccountScopeInfo,error)` 成功后，再调用现 `OpenDAGRecoveryOwner`。readonly Open 成功不是设备可信，也不构造恢复原包或降低 rotationRequired。后续认证须从同 protected slot 重新 New，不跨认证传 Workflow。

合成 Go HTTPS/race 证明 public tuple 冷重开、SHA同步、same tuple、换号/换代拒绝、CAS失败清理、缺CAS/check/冲突/closed/root/pending/journal零HTTP。没有 Android/iOS系统认证或 SDK/ABI实测，不宣称该完整手机功能已开通。
