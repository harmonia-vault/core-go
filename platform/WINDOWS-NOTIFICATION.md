# Windows 环境变更通知的失败恢复

Windows provider 写入注册表后发送环境变更通知。如果通知失败，注册表值已经改变，下一次同步可能没有任何值需要改写。此时仍必须重试通知，不能把空变更集合当成通知已完成。

provider 在任何值写入之前，将 `notifyPending` 保存到既有原值元数据中；正式受保护 provider 的该记录继续位于 Vault AEAD 内。通知成功并持久保存完成状态后才清除标记。重启、空变更重试和逐变量释放均沿用同一流程。重复通知允许发生，重复写入变量不是通知重试的前提。旧元数据没有该字段时按无待通知处理；新字段为 false 时省略。

原生 `SendMessageTimeoutW` 返回零必须视为失败或超时，即使错误码也是零。微软说明该 API 失败时不保证设置 LastError；非零返回也不能证明广播中的每一个窗口都已处理消息。[官方返回值说明](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeoutw#return-value)

通知不会强制修改既有进程的环境，Session 0 广播也不证明交互用户会话收到通知。本修复不开放正式 Windows 服务入口、不改变用户或服务身份、不安装服务、不恢复尚未验收的 profile/token 实验。

两个业务回归分别覆盖：真实 Engine 在注册表值已一致后继续报告通知失败，直至通知完成；受保护 Vault 重开及恢复原值后仍保存待通知状态。测试只使用合成内存注册表和临时 Vault，不能替代真实 Windows 注册表、SCM 或无人登录启动验收。
