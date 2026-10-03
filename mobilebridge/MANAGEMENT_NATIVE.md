# Android 受保护设备管理原生验收

## 已接通边界

Go窄桥新增 `managementDevices`、`prepareDeviceGrant`、`prepareOtherDeviceRevocation`、`managementInfo`、`retryManagement`、`cancelManagement`，profile为 `authenticated-original-transaction-v1`。Dart业务adapter只发环境、目标deviceId、角色、规范十进制期限及稳定意图id；不接收公钥、root、来源证明、封套、任意签包或原token。角色限ro/rw/admin/none，none要求输入期限0；权限、实际期限继承、HPKE和签名均由已认证Go业务重建。

六个操作都经既有Kotlin `executeWorkflow`：每次新的系统CryptoObject强认证后解包本机72B材料，打开精确绑定的独立AES上下文，本次Go对象/设备材料/软件状态钥在结束关闭。没有新增Kotlin生产绕行入口、UI改动或默认gateway放行；`realVaultReady=false`，Recovery/恢复轮换仍unsupported。

目录只返回已经验证的deviceId、role、expiresAt、keyVersion、grantGeneration管理元数据；公钥、HPKE封套和冻结来源留在Go层。准备完整原签交易后同步AES保存，未POST可以显式取消并退休原id；attempted/unknown不得取消、换id或重签。Retry先查原id/contentHash回执；未知结果仅在原期限内发送原包。已接受后必须验签Pull并完成最后原生保存才Applied=true，任何错误都不返回业务缓存。Pending期间View/CRUD关闭，认证后的Info/Retry只返回交易元数据。

全局另一设备撤销仍由Go及服务器检查当前全环境Admin，不能伪装自撤销。原120秒随机session与原签包仅在AES journal；每操作关闭后Go Restore内部保留原token用于有效期内原包提交，新的boot只用于状态查询/确认。期限失效不重POST或生成新签包。授权失效通过Go `ErrTrustInvalidated`传播，原生删除本机alias/key/state；不把403猜成管理成功。管理正常接受、Applied及未知结果分别报告。

## 2026-10-03 UTC 精确来源

本轮独立ignored `core-go/.build/native-management-snapshot`由公开归档加9个明确native候选构建，不读取其它代理未冻结恢复草稿。`export-native-snapshot.py --slice management`保留逐文件SHA256和远端main祖先检查。构建/运行/清理后 `archivedSourceChanges=[]`、当前9个候选也与运行源码一致；未声称整个当前working tree或后续HEAD已通过。

| 仓库 | 公开底座commit |
| --- | --- |
| workspace | `2ecc9cc355811bca251784d5e87cd311d0fe8d81` |
| core-go | `894f2ad8c9d05fd44b7b97533921b15ee94c76d2` |
| mobile | `3b72a29423527794c6969c6b0f9243a980ad1ddb` |
| server | `e1572d646afd6fc46fc8c7846431ddfef1a47464` |
| protocol | `b7700013c378fb59afc7d401fc1a0de05e45e458` |

候选源码：core的workflow.go、management.go、management_test.go、androidfixture/main.go、managementpeer/main.go；mobile的native_workflow_adapter.dart、NativeManagementIntegrationTest.kt、NativeManagementTestSocket.kt、native-management-test.py。导出工具、文档和mise任务不被算入9个编译候选。

- Source manifest：`5dbcb8985fddc47b8815046c6b8e4f470424c689a5ef1da8f28364168d489487`。
- 正常AAR：`b61ce06fd73c529b7fbeee7be8e1a48b3cfd2d0f15873dcc6653485023711fb7`。
- 合成Go peer：`22a88890e6afca0574c260eb2c916dc1be7e9b5803f48e681df7770e91334ac0`。
- fixture APK：`9fef41e4870c426bcd9697f4258525f1405d484ac189708af70d4ce683b81250`。
- test APK：`feb4f66e456314339cea8772e7b29e22056ab938eb6bf287dedb831aab523af8`。

固定Go1.26.4、gomobile/gobind `v0.0.0-20260908204917-8b95e45f8d3e`、BoringSSL `fab96f87245d7c6b941515201843665122650b88`、NDK28.2.13676358、Flutter3.47.6、Java17、SDK19。compileSdk36，实际隔离AVD Android14/API34 arm64。archive工具 `-buildvcs=false -trimpath`明确无VCS元数据，不冒充clean commit或字节完全可复现产物。

## 实际通过范围

快照常规/native标签桥race通过1.397/1.467秒，管理Go peer与HTTPS fixture实际编译；正常AAR、Kotlin主/test APK实际构建通过（fixture Gradle10秒），非UI adapter静态分析0.7秒无问题。首次Flutter wrapper bootstrap因未显式SDK而自动发现其它目录失败；明确固定SDK19/Java17后11.5秒成功，未安装其它NDK或接受其它工具目录license。

`NativeManagementIntegrationTest` **1/1 PASS，110.889秒，42次系统设备密码CryptoObject，真实合成Go peer exit0**。没有在本轮新增取消认证测试，不复用旧12/12或v2/v3证据。对端是成熟Go workflow的进程内合成测试设备；没有声明正式Mac CLI或桌面系统认证。

1. Android A实际注册/捕获.invalid邮件验证/完整恢复码重输双签初始化/写合成值，完整cert3 PAKE批准Go对端C；C实际双签complete、持钥boot/验签Pull/HPKE后才进入控制阶段。
2. 已验目录仅管理元数据。prepared交易阻止View；明确取消退休id，重用id冲突。attempted保存#2失败：Applied=false、服务端grant POST计数0，原prepared/attemptedfalse可取消。
3. 正常RO被服务器接受后最后保存#5故意失败：Accepted=true/Applied=false、PENDING，密封Info accepted-not-applied且View关闭。销毁临时对象、新认证后用原id确认并完成保存，grant计数仍1；C实际RO拒写。
4. 改RW被服务器接受但合成502：AcceptanceUnknown=true/Applied=false，Info原id/attempted、View关闭、取消拒绝；新对象Retry原id只查询/确认，grant计数仍2。旧RO已接受id重查不覆盖当前RW；C真实RW写入，Android验签Pull确认。
5. 改none后C缓存不再显示该环境且写入拒绝。A轮换环境至keyVersion2，再授RO；目录grantGeneration严格增加且keyVersion2，C通过新HPKE/Pull获得RO并拒写。
6. 另一设备撤销prepared尚未POST；处置临时对象、新认证/fresh boot后恢复原token/hash提交，Accepted/Applied均true且撤销计数1。C真实Pull经会话401→boot403返回授权失效、View closed。A Logout删自己的alias/key/state。

## 复现与清理

明确归档底座及候选后，在快照core-go用固定工具链构建BoringSSL或显式复用该公开源码缓存，Node依赖须来自锁文件。编译 `.build/mobilebridge/managementpeer` 用 `-tags harmonia_boringssl -buildvcs=false -trimpath`；androidfixture用 `-buildvcs=false -trimpath`。mobile `mise run go-native-build`；SDK、Java、独立Android用户目录须显式配置，固定官方Flutter bootstrap wrapper后，Gradle `-PharmoniaNativeFixture=true :app:assembleDebug :app:assembleDebugAndroidTest`只生成独立fixture包。

启动androidfixture指向快照workspace及 `mobile/build/native/management-fixture`，回环HTTPS4443使用显式合法CA链和hostname，未关闭TLS验证。只在明确合成AVD设置临时PIN/装fixture主与test APK，然后 `HARMONIA_TEST_SERIAL=emulator-5580 mise run test-native-management`，或快照 `python3 tool/native-management-test.py --serial emulator-5580`。对端密码仅匿名stdin pipe；短码仅本机test socket/native内存，不在runner args、adb shell文本、JSON/HTTP、日志或磁盘。公开控制帧只携固定阶段/sequence，只有真实Go断言成功才确认。

实际finally：本轮noBackup目录为空，alias在测试cleanup删除，PIN清除、两个fixture包卸载Success、forward为空、Go peer退出0、HTTPS96571退出0且4443连接拒绝。捕获邮件/合成账号与SQLite随临时服务停止删除。原preview仍安装，原API34 AVD57725数据和进程保留，无reset/wipe。完整manifest、driver/JUnit与cleanup只在ignored快照，未公开APK/AAR/测试钥或凭据。

受限恢复typed cert4/native lease集成、真实手机强生物/硬件证明、iOS、完整Flutter产品消费者尚未接通；本切片不打开整体ready。

手机请求公开限制：executeWorkflow/executeApproval/executeEnrollment的整段command JSON UTF8最多32768字节，含endpoint、操作id、字段名及JSON转义。Go协议value上限65536字节不等于手机可以提交64KiB；实际值余量须按完整序列化请求的UTF8字节数核算，不能按Dart字符数。变量名限ASCII `[A-Za-z_][A-Za-z0-9_]{0,127}`，`__HARMONIA_`前缀不分大小写拒绝；环境名trim后非空、最多120个Unicode码点、无NUL。Go仍是权威校验，超过原生请求上限会在认证前拒绝。
