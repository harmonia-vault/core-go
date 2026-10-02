# 后台序号通知

正式 daemon 已接通 WebSocket 通知。通知仅缩短发现变更的等待时间，账号权限、变量值和检查点继续由 HTTPS 持久拉取、签名验证与本地状态事务决定。当前仍是实验性安全软件。

## 连接与权限

受信设备完成 boot 后，使用当前设备绑定会话请求 `POST /v1/accounts/{accountId}/notification-tickets`，正文为 `{}`。随后以单次短票据建立 WSS，认证只在 `Authorization` 与设备/账号代际请求头中传递；URL 没有 query 或 token。每次重连申请新票据，不重用结果不明的票据。沿用正常 HTTPS 证书、主机名与用户明确配置的 CA 验证，禁止重定向和关闭 TLS 验证。

客户端固定使用官方维护的 [coder/websocket v1.8.15](https://github.com/coder/websocket/releases/tag/v1.8.15)，不实现自有 WebSocket 协议。应用消息限定为 1024 字节的文本 JSON，仅允许 `accountId`、`accountGeneration`、整数 `sequence`。拒绝跨账号、代际、倒退序号、重复字段、额外字段和超出协议整数范围的消息。票据、消息正文、Authorization、握手头和远端关闭原因不进入日志或错误文本。

关闭码 `4003` 只要求重新检查当前身份与授权。后台尝试受信设备 boot；只有已验证 HTTPS 请求的确定失权结果才清理账号或环境来源，不能把任意 WebSocket 关闭原因当撤销。

## 后台收敛

连接读取和心跳独立运行。消息只进入容量为一的唤醒队列，不直接写状态、导入值或推进检查点。后台 network mutex 继续串行管理 boot、拉取、显式共享写入和 verifier 生命周期。暂停时只刷新授权投影，处理签名撤销/删除，不应用变量变化或推进数据检查点。

每次成功重连主动拉取；断线期间丢失通知也能按持久序号补漏。连接失败使用带抖动的指数退避，最大一分钟；库的 Ping/Pong 定期检测断链。既有轮询兜底和本地到期 ticker 保留，授权到期即使没有网络或关闭消息也停止生效。退出账号和停止 daemon 会取消并等待通知读取、心跳和在途请求，再清除设备材料。

普通拉取在途遇到用户暂停时，状态事务原子拒绝新值；迟到响应只能验证当前签授权及环境生命周期证明并应用授权投影。数据序号保持原值，恢复后授权序号领先会触发完整补拉。伪造的 grant 不会因投影被接纳。

## 已验证与门槛

通知与暂停竞态的合成 race 回归通过：非法消息/错误脱敏、重复提示合并、取消/旧 epoch、断线持久补漏、暂停授权变化、有效与伪造撤销、迟到数据拒绝及恢复完整补拉。

正式 daemon 编排测试使用临时加密目录、合成双签入网回执和一小时轮询间隔，验证实际 HTTPS boot、WSS 唤醒、暂停授权投影、断线漏通知后重连补拉，以及 `4003` 后 boot 确认失权。它只验证后台调度，真实 SPAKE2 入网由 workspace 另项验收覆盖。

workspace 的独立通知验收已实际连接 Go→HTTPS/WSS→正式 TS Node 通知适配→临时 SQLite，验证单次票据、当前权限检查、签名/HPKE/AEAD拉取、断线补漏、暂停与撤销。只使用合成数据和 loopback 服务，未安装宿主服务或部署线上实例。

服务端契约见 [server 通知说明](https://github.com/harmonia-vault/server/blob/main/docs/NOTIFICATIONS.md)。Windows 本机 Service/DPAPI/ACL 与通知联合运行尚未实机验收；三平台编译不能替代这些门槛。
