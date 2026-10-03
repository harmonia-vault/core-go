# 连续恢复原生验收记录

2026-10-03 UTC。固定公开源码归档加 15 个明确原生候选的同一份正常 AAR、主/test APK，三阶段实际全部通过，合计 94.475 秒。本文不把当前工作树、新登录/Pending/PIN/UI 草稿算作该产物。`realVaultReady=false`；默认 gateway 是否开放单操作须另行完成产品接线，不能据此宣称生产可用。手机合同见 `mobile/docs/NATIVE_RECOVERY_ABI.md`。

## 保护与接口边界

每个操作重新由 Android 系统强认证/CryptoObject 解包设备材料，Go 校验受保护上下文。旧恢复 Ed owner 只保存在 Go 进程 registry，opaque handle 不进入 Dart、JSON 或磁盘；Begin/Complete 中的恢复接收私钥当次清除。普通 Workflow.Close 只 detach；认证取消、保存失败、logout、失效、回拨、期限和 dispose 都退役 registry owner。原 25 域两签包同步密封后即退役旧 owner；unknown 只查/retry 原 journal，不复活旧私钥。成功轮换仍 restricted，必须显式环境/角色/期限登记；正式 Boot/Pull/proof3/最后保存全部成功才 trusted。

10 个恢复和 4 个显式 V4 批准操作没有一般签名、恢复 handle 或私钥导出，没有新增管理者 rotateRecovery API。整个请求最多 32768 UTF-8 字节。没有修改 Flutter UI或编写 UI 测试。合成完整恢复码及 PAKE 短码只通过匿名 pipe/局部 ADB socket 内存传送，不进入 instrumentation 参数、shell 命令、服务器 HTTP、日志或磁盘。

## 最终固定来源与产物

最终 ignored 快照为 `core-go/.build/native-recovery-role-snapshot`。公开底座：workspace `14a27f9a368e03d241cad8ae88fb777e6269666d`、core `6eec463eecc0e14f18dcb0ddd29ae2bcd98cad94`、mobile `d169d74d5c7bf080d02e950e6a8147d21175cc5b`、server `02689b44e071cfdfe0aa3c65d7a5d250c3c69fe8`、protocol `de21d9907dd7b73636afeabee4806655aaa0a82e`；加 source-manifest 明列的 10 个 core 和 5 个 mobile 候选。CLI 使用 buildvcs=false，归档无 VCS 元数据。构建/运行后的 `archivedSourceChanges=[]`。不声称当前 HEAD、整个工作树或二进制字节完全可复现。

| 最终产物 | SHA256 |
| --- | --- |
| source-manifest.json | `c7630a1971f3fe153543dc02f2a75dddaa2db697d109f1b8e0b2a8f1ce06fb7f` |
| 正常 harmonia-go.aar | `54b4d03dc4fccaeec9cebf0655f6e15f14bc86a49c19d512865a9ccdfee8766a` |
| 正式 compiled Mac CLI | `3d0188b16c5bfff573bda00e808e7d9a94da399ad770a11f7656a5496bf0107a` |
| recoverycontroller | `657868ecc359c572a3c42efc188d2b16ac4cbd8ff014672b8673452671b61b14` |
| crosscontroller | `d4b68a5147f2a37f5a6eb7b52b3e2b28f5632da4a62b7ec6ab0f5c2822ff138c` |
| HTTPS fixture | `f30785956cc76f22e96e9b95bc9797770a785016033708c4e64e154d860311e8` |
| 独立主 APK | `ac95d9496b1d026560bcd3e97451334970e6c61e99ddc6ea5e9f9d0377b16f5e` |
| 独立 test APK | `539cb15870e430b6b0f246ef213763d2092949b40886bf8bf89b27f05a681b9b` |

工具链为 Go1.26.4、gomobile/gobind `v0.0.0-20260908204917-8b95e45f8d3e`、Flutter3.47.6、Java17、NDK28.2.13676358、BoringSSL `fab96f87245d7c6b941515201843665122650b88`。正常 AAR、正式 CLI/controllers 和真实独立 fixture 主/test APK 构建通过。compileSdk36，实际运行 Android14/API34 arm64-v8a，不能混称运行 API36。最终 Go 编译源码与前一 clock 快照相同；该源码普通/native bridge 与 registry race 已通过（1.451/1.459、1.419/1.320 秒），最终只改测试角色字面值后重新构建全部正常产物，没有把未重跑的当前 Go 树记作新 PASS。

## 同源三阶段实际结果

| 阶段 | 实际 JUnit | 证据 |
| --- | --- | --- |
| 1，PID5644 | PASS38.985s | 系统取消关闭 owner、不返回受限值；有效完整旧码 resume；受限 X KV2/Y 已验值；原25签包密封前失败0POST；服务器接受后502及原ID查询。 |
| 2，PID5902 | PASS21.174s | 第一次真实 force-stop 后完整新码继续原包、full-vault/save 后新 RAM owner；普通 View 拒绝；显式 X RO1小时/Y Admin0 登记；真实服务器接受后最终 Applied seal 故障，trusted=false/owner和cache关闭。 |
| 3，PID6067 | PASS34.316s | 第二次真实 force-stop 后原 cert4 ID retry 无额外POST，Boot/Pull/proof3/final-save 后可信 E；真实 X拒写/Y写；Android E 显式V4批准正式CLI4有限RW Y-only，完整PAKE/双签/Boot/已验Pull/隔离导出/RW写及运行中daemon拒X；原ID确认complete并验CLI写；Logout删除本机钥/state。 |

共 30 次真实系统 CryptoObject 提示，含 1 次取消；两次真实进程停止、三个不同 PID。两个 controller 均 exit0。最后保存故障按包公开 AAD checkpoint>0 选择 Applied 阶段，不以第几次回调猜阶段；生产 hook 默认空。实际 saves=6、challengeStatus=200、deviceAttempts=1、deviceStatus=200、最终 seal 故障命中。最终公开计数 approvals=0、approvalsV3=0、approvalsV4=1、recoveryTransitions=1、recoveredDevices=1、recoveredDeviceAttempts=1、mutations=4、revocations=1；不会以只计200成功数推断未发送请求。

## 历史失败与修正

前三次使用上述 workspace/mobile/server，core `1be168018ed7bafd052422604dfe2ed3b78db3d2`、protocol `b7700013c378fb59afc7d401fc1a0de05e45e458` 加15候选。以下失败保留原日志/manifest，不与最终阶段拼接。

| ignored 快照 | source-manifest SHA256 / AAR SHA256 | 实际结果 |
| --- | --- | --- |
| native-recovery-snapshot | `85ec63174464efae0c1e5fbb9ee5d06779ee830458a61f51f1ad15dba71141ab` / `a04c6c3f1752764ddb39e76f325b9d9d775f2c03a8221c19eff87c9a79c242ab` | 阶段1 FAIL19.446s，8提示含1取消；夹具错误地期待真实保存失败返回业务JSON，实际固定 PlatformException 合理。阶段2/3未跑。 |
| native-recovery-retry1-snapshot | `d4f6bf80bee5ad9978d5df8c215befb2e0d1c110a7f7c80af9d30a0969327d5c` / `3f528fd0add77cbcf2c22b6ecd82d8b4633b5ba0503e0925035a48038992f1b7` | 阶段1 PASS33.462s；阶段2 FAIL11.216s登记REJECTED；阶段3未跑。旧成功counter=0不能证明0POST。 |
| native-recovery-finalphase-snapshot | `22793f4764502a04866c5957cd4d805da721e818e9bbd346290d5f13a753031c` / `17087d59387c43f466ebce139609c821b5277fca563a04405b2170babe8384f8` | 阶段1 PASS34.359s；阶段2 FAIL13.693s，共17提示含1取消；实际challenge200/deviceAttempts0/saves2，首次原包密封与POST前拒绝；阶段3未跑。 |
| native-recovery-clock-snapshot | `ef20b687bf0a3bb13fa5628a590145c813218f5a87ecada73b3b89f69ca0c38a` / `abad4c958316ceb90397abc37663f3641e62a5a136a4d17c59cf6b26622471f6` | 新公开clock底座；阶段1 PASS34.129s、阶段2 PASS21.707s；阶段3已原ID恢复可信E/View后，夹具错误期待ReadOnly，实际公开枚举RO，FAIL8.174s；CLI4/V4未跑。 |

AVD 比宿主慢约350ms，Unix秒边界能使原120秒挑战被手机严格签名校验判作121秒。隔离Go真实HTTPS已复现3秒lag和350ms跨秒边界；公开6eec的窄修先验证完整source/role/KV，再以ctx与monotonic最多5秒等待真实钟自然进入原严格120秒窗，同步保存/检查owner期限。不改crypto/server120秒、原ID/Expires/owner期限或时钟。clock快照已证实实际登记/最后seal门槛；最终快照只把测试ReadOnly字面值修为RO，其他14候选SHA与clock快照相同，重新完整运行三阶段才获得最终PASS。

## 清理、复现与未跑边界

最终 finally 删除本轮合成noBackup文件，读回为空；系统PIN清除返回Lock credential cleared；nativefixture和nativefixture.test均卸载Success，UID Keystore槽随对应包删除。CLI/provider合成目录与controller进程均0、ADB forward为空；HTTPS48590退出0、4443连接拒绝。原 preview 包存在，同API34 AVD数据保留无reset/wipe，模拟器会话57725继续，已交回UI视觉验收。只有本轮Python字节码缓存被删除。日志、source/artifact manifest、runtime和cleanup只留ignored快照，不公开二进制/私钥。

复现入口为明确隔离AVD上的 `mobile` mise任务 `test-native-recovery`；先按export工具选择上述公开commits与有限候选，构建正常AAR/CLI/独立APK，再用合成PIN、显式合成CA合法TLS链及局部socket运行三阶段，finally清自己资源。该证据覆盖第一条连续恢复→直接登记E→E批准CLI4；没有覆盖DAG第二次恢复、普通非恢复V4审批、App PIN、真实手机/强生物成功、桌面系统认证或真实邮件服务。新login/pending/connection/restore与Flutter产品用户链另作切片，不打开整体ready。
