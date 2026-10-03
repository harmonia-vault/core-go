# App 重启后的原业务事务重试

已通过本机系统强认证的原生持钥层可列出本机保护日志的待处理事务，再按原 ID 查询或重试。该入口不接受变量名、值、环境名、替代封套、签包或新授权意图，也不从云端同名值猜请求是否成功。

```go
items, err := workflow.PendingBusinessOperations()
result, err := workflow.RetryBusinessOperationByID(ctx, originalID)
```

`PendingBusinessInfo` 只含 `id`、`operation`、`environmentId`、`state`、`sequence`、`applied` 六个元数据字段。`sequence` 是最后已知的接受序号；非零不等于所有项完成。状态为 `unknown`、`accepted-not-applied`、`applied` 或 `canceled`。只有本次调用无错误且 `applied` 为真，才向用户报告本次确认完成；任一保存失败都返回 `applied:false`。

名单不联网，最多 32 个变量事务加 32 个环境事务，按原 ID 排序，不包含变量名、值、密文、摘要、签名、token 或钥匙。变量事务通过成熟 Writer 的已核验日志元数据助手读取，不能在手机层猜日志格式。环境事务来自原生保护的完整原环境签包。不同日志共用同一 ID 时拒绝，不能猜用户要重试哪项。已应用记录不再列入待处理名单，但原 ID 仍可明确再次确认，防止已密封完成却丢响应后伪报不存在。

变量重试仅调用 `WriteRequest{ID: originalID, Operation: "retry"}`，其余字段全部为空。成熟 Writer 逐个查原签包精确状态、当前权限和版本，然后经相同验签 Pull 确认原 ID、签包摘要与序号。已取消项只有元数据墓碑及历史查询资格，不能重新签包或重投。批量导入元数据以受保护签 mutation 描述，多项 put 显示为 import，不返回输入名字或值。

环境重试仅调用原记录的 `submitRecord`：保留原环境 ID、密钥、封套、origin、idempotency ID 和期望序号；按该原记录的能力路由查精确 contentHash 与原事务检查点，经相同 Pull 确认，不自动把旧包升级到新 profile。权限变化仍逐请求检查。失去账号或设备信任时清理本机保护资料；其它原有自撤销、恢复、入网、审批、管理未决门槛继续优先，不能借重试读取离线明文或绕过当前权限。

## 独立公开快照实测

以公开 workspace `14a27f9`、core `1be1680`、server `02689b4`、protocol `2edad19` 创建独立 `/tmp` 快照，只叠加 `pending_write.go`、根代理的 `syncclient/write_pending.go` 与新 `acceptance/mobile_pending_write_test.go` 三个候选文件；不混其它来源图草稿。

一项真实 HTTPS / TypeScript / SQLite / Go Ed25519、HPKE、AEAD 验收通过：变量服务器接受后 502 → 真正关闭并从 AES 保护状态 New → 只读待处理原 ID → 原包状态与 Pull 确认 → 已 applied 原 ID 再确认；环境 create 接受后 502 → New → 原 origin 签包重试 → 正确环境名、无重复环境。变量与环境各只 POST 一次，未记载 ID 拒绝，不新建事务。Go race 总计 3.078 秒；两个包的默认构建 race 分别 `mobileworkflow` 3.076 秒、`syncclient` 8.811 秒；vet 通过。该场景无需 PAKE，不把默认构建的原生 PAKE 跳过算作通过。

最终源码补齐跨日志已 applied ID 碰撞检查后，在同一公开快照重跑该真实场景通过：主测试 1.59 秒、Go race 总计 3.062 秒；最终业务包 race 3.027 秒，vet、源码扫描与 diff 检查通过。

原生 Android 的新待处理名单和原 ID 重试桥、App kill 实机与 UI 接线尚待独立验收；本组件不宣称生产可用。
