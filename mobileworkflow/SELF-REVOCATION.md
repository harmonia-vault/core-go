# 手机自撤销的受保护事务

实验性首根管理手机切片。设备必须拥有所有当前环境的 Admin；普通某环境 Admin 不能据此撤销跨环境设备。服务端每次检查账号代际、设备及会话、双公钥、权限版本、短时 nonce 和精确设备签名。撤销接受后立即删除自身会话和授权。

原生 API 为 `RevokeSelf(ctx, id)` 与纯元数据 `SelfRevocationInfo()`。完成接口返回 completed、sequence、deviceInvalidated、acceptanceUnknown、expired；deviceInvalidated 要求原生删除受保护状态、设备材料与密封 alias。错误发生时仍检查这个结果，不只检查 Go error。

受保护日志保存原签包、原幂等 id、账号/设备/epoch、基准持久序号与原随机会话。签包把原 session hash、两公钥、全部当前授权版本与一次 nonce 绑定。密封写入成功前不发送完成请求；重启重新验证所有绑定和签名，精确重投同一个包。token 不进入 Dart、日志或明文文件，也不会因为重新 boot 而重新签包。正常操作关闭会清进程材料并关闭 HTTP 空闲连接。

结果未知时先查原 id。原 status 返回 401 后，真正的持钥 boot 若返回 device_untrusted，说明授权已失效；不能据此断言本地那次 id 已接受。此分支返回 completed=false、acceptanceUnknown=true、deviceInvalidated=true，擦缓存、信任、日志和进程钥，持久关闭账号。只有精确已知 200 完成回执会返回 completed=true。另一个管理设备撤销也可能导致同样的 boot 拒绝。

未决时禁止普通 Pull/View/CRUD，避免继续显示离线明文。原挑战过期后首先擦除日志中的 bearer 并密封，再尝试用新的合法会话只读查询原 id；旧签包不再 POST，也不隐式换 id。expiry 本身不能证明原请求未曾接受，所以仍报告 acceptanceUnknown。可继续查看纯元数据或真正退出清理。

## 已运行的验证

- Go race：mobileworkflow 与 syncclient 全包通过，2.206 秒 / 3.752 秒；覆盖挑战字段替换、保存失败、精确恢复重试、到期擦 token 与待决 gate。
- 真实 Go→127.0.0.1 HTTPS→TS/临时 SQLite 的 5 子项通过：已知 200；真实接受后 502、重启原 status 401→boot 403；接受前 502、重启字节一致原 token/原签包成功；native 保存失败完成 POST 为 0；客户端时钟越过窗口后原 token 擦除、无再次 POST、结果仍未知。最后一项只调整客户端时钟，未伪造 Node 服务端时钟。
- 真实 HTTPS 手机原纵链与上述 5 子项的 race 包通过，6.240 秒。
- Android 原生高层 suite 12/12 通过，184.013 秒；代理记录系统 PIN 认证、两种自撤销结果、pending 元数据与 View 拒绝、密封文件和 alias 清除。由原生组件独立记录，不把 Go AES 替身当作 Android 安全认证。

测试只使用随机合成钥、.invalid 邮箱、捕获发信替身、临时 SQLite 和隔离 AES 文件。未读取用户真实凭据或宿主环境。软件钥及运行时副本不能保证始终硬件内；该验证不是生产安全审计。
