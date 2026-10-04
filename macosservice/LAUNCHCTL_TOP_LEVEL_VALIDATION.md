# launchctl 顶层字段窄修

`launchctl print` 的 resource/jetsam 等嵌套块也有 `state`、`type` 字段。旧解析器逐行扫描全部层级，会把合法运行的服务误判为重复身份字段，从而让 Start 的后置核验失败。

共享有界解析器现在只返回顶层身份、状态、PID 和 arguments；服务身份、完整参数、UID、CA、规范 PID 和启动中状态的原校验仍保留。`launchState`、`observedJob`、`jobPID` 共用同一层级规则，未新增服务运行机制。

## 验证

旧实现的定向用例复现“合法嵌套被误判未知”。接入修复后，8 个受影响用例通过，包含嵌套字段与 PID、顶层重复、边界括号、身份/CA/参数不匹配、非法 PID 及 starting 状态。定向 vet 与正式管理工具构建通过。入口为 `mise run test-macos-launch-print`，本段使用固定 Go1.26.4 执行相同范围并保存 JSON 结果。

用例复用了先前真实 VM 只读投影确认的嵌套形状，原始 launchctl 输出没有保存，因此不是原始全文重放。此前 Install、配对、BootPull 证据复用，本段没有重跑完整生命周期或全量测试。

本段新的实际服务启动核验未执行：精确合成 VM 窗口的首次识别成功，后续截图前守卫报告窗口不唯一。未发送输入、安装更新、Start 或 Stop。UTM 的只读列表仍显示目标 VM 已启动，但这不能证明服务状态。未改变宿主服务或安全权限，也未修窗口控制框架。

结果见 `evidence/launchctl-top-level.json`。Mac 完整生命周期仍未验收，Android 认证链也仍未验证，不能宣称生产可用。
