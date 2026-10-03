# Type=exec 原生文件系统合同验证

当前结果：固定公开 core `b06302c541ce36edf8828f651ae342c535428a77` 加两处测试修正，在既有隔离 Ubuntu ARM64 完整内核 VM 上固定 5 主项、4 子项全部通过，0 失败、0 跳过；原生测试 0.899 秒，整轮 1.759 秒。产品源码未修改。

测试通过注入的 manager/helper 验证 root 临时文件系统合同，没有执行真实 systemctl 控制、登录、Start 或 Uninstall。真实 Type=exec 启动及 Boot/Pull 仍未运行。主机 race 的 131 个主/子结果通过，ARM64 编译通过；编译结果独立记录，不计作原生运行。

修正了新增测试对从未启动的 installed-disabled 分支要求 Stop 的错误断言。该分支应执行零次 Stop；active 分支应精确执行一次 Stop；两者都必须 drain。两个分支先模拟 drain 返回 ErrBusy：要求不完成、不登出、不删除，原回执及全部实际创建对象保留、journal 仍为 uninstall-requested；解除 Busy 后通过同一 journal 正常重试。未改产品 Stop 条件或权限检查。

其他合同覆盖严格历史 simple 模板实际字节、带授权材料的 stopped/pending-enable 回执安全卸载、有效 Type=exec 不受支持时保留回执且可卸载、enable 隐式 reload 改变有效类型后零次 start。

前次任务专用临时目录经其固定 SCOPE、ELF、对象集合及当前身份认证后精确清理；新 exclusive 临时目录运行完成后精确清理。既有合成测试账号的正式安装目录、授权状态、回执与启用链接前后核验保持不变；未读取其私有叶内容。

历史失败均保留：第一轮 host 公开归档源码 metadata 拒绝，未连接 VM；下一轮原生 4 主项通过/1 失败、3 子项通过/1 失败，失败为上述测试断言；随后 host 重复输入检查又因两个公开测试源的归档权限拒绝，未连接 VM。最后限定 host 读入修正只对这两个精确 source-map 绑定路径采用公开源码策略，其完整大小、SHA、owner、single-link 与读前后身份仍严格核验，执行输入和 SSH 材料规则不变。原生失败的第一份本地计数投影漏识别含连字符子项，原文件保持，另存正确 3/1 投影。

实际来源、测试名、8 个阶段检查、原始日志和产物 SHA 见同目录 `systemd-exec-native-contracts.json`；不据这些注入合同宣称真实系统启动或生产可用。
