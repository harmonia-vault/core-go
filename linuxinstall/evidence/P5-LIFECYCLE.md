# Linux P5 生命周期：分段实际证据

正式卸载续办、新合成真实 shell 验证和精确身份清理分别通过。原完整运行在最终离线卸载阶段的 **FAIL 仍保留，原因尚未确定**；原 post-reboot shell 的自动逐 key 恢复没有执行，仍为 **UNRUN**。本记录不把分段成功改写为一次无故障的整轮通过，不代表发布或部署。

| 实际范围 | 结果 | 耗时 |
| --- | --- | --- |
| 原完整 P5 运行 | FAIL：最终正式离线卸载返回 `linux_install_state_invalid` | 26.089s |
| 同回执、同 journal 的正式卸载续办 | PASS | 1.659s |
| 独立合成真实 `/bin/sh` 自动恢复 | PASS；不接回原 shell | 0.776s |
| 仅本次合成 UID/GID 与 PASS 诊断对象清理 | PASS | 0.722s |
| 原 post-reboot same-shell 自动恢复 | UNRUN：进程已在原失败后退役 | — |

既有隔离 Ubuntu ARM64 完整内核 VM 使用正式 systemd 安装器。运行输入为 core `78d7dd845307abb9566cf8a6d0711c4977841c11`、server `36ab16fbaadacd766548e201c05acd5e80ccb89b`；配对 CLI 为 CGO1/BoringSSL 原生 PAKE，certificateVersion3。没有用 CGO0 配对或注入可信状态。

原运行在失败前实际完成了：legacy 回执正式离线卸载、新 Type=exec disabled 安装、正常 CLI 配对和密封接受回执、正式 Start 后 HTTP200 Boot1/Pull3、真实 IPC/合成 shell 断言，以及一次正常重启。重启后目标 UID 登录会话0，服务新 Boot1/Pull1；正常 Stop 保留配置且 Stop 窗口 HTTP0。首个 shell 的显式 `harmonia_refresh --release` 已证明原 key 恢复、新 key unset、无关 key 保留。

正式卸载续办仅添加四个已审 test-only Go 阶段观察点/入口，保留正式 coordinator 的权限、身份、drain、离线 helper、最终槽位缺失、持久 journal 和删除检查。诊断协调器为 CGO0 ARM64，真正离线 helper 仍是已安装的原生 CLI。helper exit0、stdout41字节（成熟成功 DTO）、stderr0；最终 fault NONE。随后实际确认 state/IPC、程序/CA、unit/enable link、receipt/journal/guard 缺失，unit not-found，UID进程0、cgroup空。原卸载失败没有被归因为某个产品原因，也没有据此宣布故障已修复。

独立 shell 使用当前公开 core `c5866f59299cbb6838c3f753dda7aaefeb7fcf82` 的 `RenderPOSIXFragment`/`RenderShellHook`，在现合成用户的新独占临时目录内运行一个 `env -i /bin/sh`。仅三个固定合成变量：片段单独缺失时保留配置；同一 shell 删除自己的 owned 目录后，普通 `harmonia_refresh` 恢复原值、unset工具新增项、保留无关项。临时目录已清除。**这是模拟目录删除的独立合同验证，不能替代原未执行的 same-shell 断言。**

最后只清理已核完整 SHA、root身份和固定文件集合的三个 PASS 诊断对象，以及本次合成 UID/GID31042。账号名称/UID、组名称/GID四个实际索引均不存在；旧范围相对受审重启 witness 保持一致。原 FAIL ROOT、原日志和构建证据均保留；共享管理父目录/锁按设计保留，没有泛删、再次 Start、重启、换 CA 或重跑全链。

脱敏结果、输入版本和原始证据摘要见 [linux-p5-lifecycle.json](linux-p5-lifecycle.json)。它不包含密文、环境值、凭据、邮箱、token、测试 SSH 材料或宿主私有路径。此前构建/探针/宿主预检失败均另行保留，没有覆盖原记录。
