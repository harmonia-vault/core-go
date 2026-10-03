# 账号、可信会话与原业务事务原生验收

2026-10-03 UTC。四个独立意图 `loginAccount/restoreSession/businessPendingInfo/retryBusinessOperation` 已由固定公开 Recovery 底座加7个有限候选的同一正常 AAR 完成 Android 三阶段实际验收，合计62.370秒。未改 Flutter UI，没有UI测试；不把当前工作树、App PIN、新instance-info或产品TLS入口算作该产物。整体 `realVaultReady=false`，产品 gateway 可按实际单操作能力接线，Flutter 用户链仍须独立运行。手机严格DTO合同见 `mobile/docs/NATIVE_ACCOUNT_PENDING_ABI.md`。

## 安全与业务边界

每个操作新的系统强认证/CryptoObject解包本机材料，Go校验设备与AES受保护上下文。`loginAccount(email,password)` 只在成熟Go标准HTTPS真实登录成功后返回 `{authenticated:true,trustedDevice:false}`；当次随机session随Workflow.Close清，不授予View/Pull或设备可信，不持久密码。初始化、入网、恢复下一操作仍JITLogin。

`restoreSession()` 先通过成熟Go View的已验来源、有效权限与同步最后保存，再精确匹配本次AES认证内层account/generation/device/checkpoint，才投影 `{trustedDevice:true,accountId,accountGeneration,deviceId,view}`。登录、未可信、restricted或尚未Applied入网不能返回该DTO。它恢复已验本地cache，不联网；新的Pull仍独立认证与在线检查。没有审批来源版本字段，冷恢复之后不能从公钥/root猜V3/V4或试错降级。

Pending只给 `{id,operation,environmentId,state,sequence,applied}`，不含变量名/值/token/签包；列表最多32变量写+32环境交易。Retry仅原id，不能替换name/value/env或重签。变量unknown返回PENDING；环境HTTP结果不明可返回REJECTED+retrySameId=true，两者都须保留原密封journal。REJECTED不表示确定未接受，不能换id。Applied只有当前验签下发和最后保存全部成功且无error才为true。每条command最多32768 UTF-8字节，其他成熟角色/来源/缓存/save门槛不放宽。

## 固定来源与精确产物

Ignored 快照 `core-go/.build/native-account-baseline-fixed-snapshot`，公开底座：workspace `409fd52e632c331d03b45d919fb9e08871323ab7`、core `5040921e1867578be291b985736811326ed8ae6d`、mobile `56ac910d4c1778083d94fe2091a84392aa603362`、server `02689b44e071cfdfe0aa3c65d7a5d250c3c69fe8`、protocol `de21d9907dd7b73636afeabee4806655aaa0a82e`。下面7文件为唯一源码覆盖，归档无VCS metadata，fixture以buildvcs=false编译。构建和运行后 `archivedSourceChanges=[]`；不声称当前HEAD/全工作树或二进制字节完全可复现。

| 候选源码 | SHA256 |
| --- | --- |
| `core-go/mobilebridge/business_intents.go` | `ddb83904374f1227c8aeebaab911ddccc24ff77a1752691e120fa865d56fab7a` |
| `core-go/mobilebridge/business_intents_test.go` | `8bd772f7f43adcb9acfcbd37f8b9c0af49d522d696ac3c1d8fccfd364ba98d98` |
| `core-go/mobilebridge/cmd/androidfixture/main.go` | `eea6f210f4dbe85b1daa5e479c35188f7c7f9552513968fb6812bff74000367a` |
| `core-go/mobilebridge/workflow.go` | `61a5c240bb0692f4b9038748df67833bdae744e82d393f5227659958d82ad6e0` |
| `mobile/android/app/src/androidTest/kotlin/org/harmoniavault/harmonia_mobile/nativebridge/NativeAccountIntegrationTest.kt` | `9451f783b34604afd4c4449453a9f6b59aafa071ea562c42632fb5221435b1fb` |
| `mobile/lib/native/native_workflow_adapter.dart` | `ce194b4b1691e2b718e05f0c34f3799b403791cad18ad6619d6cff934a5f6c55` |
| `mobile/tool/native-account-test.py` | `44a8a3e37e7def29449ee1633411607c0ea5b03202cd902d709f8fb0d1f11043` |

| 产物 | SHA256 |
| --- | --- |
| `source-manifest.json` | `a8848ce5fc1ae7d20a89107e60da81eb781ff5777aca3f80b7528eed6d69d9a7` |
| `mobile/build/native/harmonia-go.aar` | `7af225529d2d5cea6c435e28f568e7d3a3cd523688ed8a966be16dd1dfed1e08` |
| `mobile/build/app/outputs/apk/debug/app-debug.apk` | `b0b51ecfb29fce4955b3359d561025fdc57525e13f0a0d128066971db9c9f669` |
| `mobile/build/app/outputs/apk/androidTest/debug/app-debug-androidTest.apk` | `2bdba40d40becef833ef714fd28e10f69d7a73db0534de29aa4d42c1f83e43a2` |
| `core-go/.build/mobilebridge/androidfixture` | `4b0f5da5cff85bd217c9afdd3f33e47186e467952c1ea918e675ba777b124dc5` |

固定Go1.26.4、gomobile/gobind `v0.0.0-20260908204917-8b95e45f8d3e`、Flutter3.47.6、Java17、NDK28.2.13676358、BoringSSL `fab96f87245d7c6b941515201843665122650b88`。正常AAR、主/test APK和HTTPS fixture实际构建通过。compileSdk36，实际Android14/API34 arm64-v8a。独立Go账号标准HTTPS/错误密码/未知CA拒绝/登录不授trust/严格字段测试和bridge/registry常规与native race已在首固定快照通过；最终production helper、dispatcher及其测试SHA相同，仅fixture路由计数和Android断言修正，未将未重跑的当前Go树冒称新PASS。业务adapter analyze通过。

## 同源实际三阶段

| 阶段 | JUnit/PID | 实际证据 |
| --- | --- | --- |
| 1 | PASS29.498秒 / 8904 | 新设备注册、合成邮件证明；错误密码拒绝；真实登录只未可信；restore拒NOT_TRUSTED；完整初始化重输后投影精确账号/gen/device；变量accepted502、unknown/appliedfalse原journal。 |
| 2 | PASS17.077秒 / 9134 | 第一次真实force-stop后原变量id续办Applied、mutation仍1；restore已验值；环境create accepted502返回REJECTED+retrySameId，原journal unknown/appliedfalse；严格baseline1→delta1→total2。 |
| 3 | PASS15.795秒 / 9286 | 第二次真实force-stop后原环境id续办Applied；再次原id查询不增POST/checkpoint；restore两个已验环境；Logout删alias/key/state；后续restore平台PROTECTED_KEYS_UNAVAILABLE拒绝。 |

22次真实系统CryptoObject提示，两次真实进程停止、三个不同PID。本轮无新增取消场景，不复用旧恢复或管理取消证据。最终公开计数mutations=1、environmentChanges=2、environmentAttempts=2；初始化成功后成熟Go还会rename初始环境一次，故baseline1，测试create严格新增1，原id两次续办增加0。记录在artifact/runtime/JUnit/counters，无凭据或恢复码输出。

## 历史失败不拼接

首轮source2501ab70/AARf15a3bc7：阶段1PASS29.976秒，阶段2旧fixture没有匹配真实environment-changes-v2/v3而错误返回成功，阶段3未跑。次轮source86d47559/AARf278e4de：阶段1PASS33.577、阶段2FAIL12.540，夹具错误期待PENDING，实际成熟环境原包HTTP错误为REJECTED+retrySameId；第三阶段未跑。该轮没有可靠最终计数，不追认accepted1。

第三轮source9891eef7/AAR07fb2d5e：阶段1PASS29.862、阶段2FAIL16.107，16提示；实测environmentChanges2/attempts2/status200/controlStatus200/mutations1，夹具错误忽略初始化rename基线。root审阅Go初始化与fixture后，仅批准baseline1、create delta1/total2、phase3原idretrytotal2不增。最终相对第三轮仅Android测试该一文件SHA变化，完整重建并从阶段1重跑，未拼接旧PASS。多余未构建export目录不计产物；APK未安装的setup错误均0提示/测试主体未运行，保留preinstall-unrun日志。所有失败来源与日志仅ignored，未改生产业务以适配测试。

## 复现与清理

由 `mobilebridge/tools/export-account-snapshot.py` 给上述五个完整public SHA导出新ignored目录，只覆盖上述7文件。按 `mobilebridge/build-android.sh` 显式传mise固定SDK/NDK/Java构建正常AAR，`go build -trimpath -buildvcs=false ./mobilebridge/cmd/androidfixture`；固定Flutter locked离线依赖，显式SDK local.properties。用 `-PharmoniaNativeFixture=true` 构建独立nativefixture主/test APK，启动只有合成.invalid邮箱和临时SQLite的本机HTTPS fixture，CA私钥只进程RAM。安装独立包后，明确隔离emulator与合成PIN，运行 `HARMONIA_TEST_SERIAL=emulator-5580 mise run test-native-account`；runner逐阶段调用真实NativeBridgePlugin并force-stop两次，调用者finally清理自己的PIN/包/服务，不能将该入口用于真手机。

最终本轮noBackup测试文件为空，实际Logout验alias删除，PIN清除，两nativefixture包卸载Success，ADB forward空；HTTPS96060退出0、4443拒连接。原preview与同API34 AVD57725保留，无reset/wipe。source/artifact/runtime/counters/cleanup留上述ignored快照，未发布二进制或自提交。正常ignoredAAR可供下一产品构建复用，但不是Flutter产品链通过证据。新instance-info/注册策略、公开端点留存、productfixture TLS注入、审批来源能力投影、App PIN和iOS不属于本证据。
