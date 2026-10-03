# Android cert3 来源授权原生验收

## 已接通的窄业务边界

`workflowProfile`逐项声明`approvePairingV3/retryApprovalV3/approvalInfoV3/cancelApprovalV3`、`enrollDeviceV3/resumeEnrollmentV3/enrollmentInfoV3`与`rotateEnvironmentKey`。旧`approvePairing`继续明确调用首根v2，没有猜版本或失败后降级。`realVaultReady=false`、Flutter默认gateway和UI保持关闭；恢复与恢复轮换继续unsupported。

Kotlin新增`executeEnrollment`，同`executeApproval`一样只接受精确`command + ByteArray shortCode`；短码不进JSON、日志或文件。Go在同一次已成功的系统CryptoObject认证内连续Login+完整cert3 PAKE，局部context最多120秒，其它操作30秒。原生每次重新认证、打开72B设备材料与独立软件AES状态，结束关闭临时Go对象及可控缓冲。Dart业务adapter只发送意图，不做密码学、来源证明、封套或权限判定。

可信入网必须完整双签、已接受序号、已验origin账本/检查点、HPKE/AEAD及最后一次原生同步保存全部成功。服务器已接受但Applied保存失败返回PENDING且无view；`enrollmentInfoV3`只给元数据，trustedDevice仍false，View/CRUD关闭，只能原receipt/id Resume。manager批准unknown也保原签journal和view/write gate；只有候选双签complete被核验才报告complete。来源与最新环境授权全由已认证本地Go重建，不接收Dart的root/证书/issuerProof。Go的来源权限拒绝`ErrWritePermission`映射UNAUTHORIZED，没有改变权限判定。

## 2026-10-03 UTC 固定源码与产物

使用公开源码归档加10个明确native候选文件，不读取当前其它代理未冻结的RecoverySession/management草稿。`mobilebridge/tools/export-native-snapshot.py`只写新ignored目录，拒覆写并产生逐文件SHA256；构建后及运行后`archivedSourceChanges=[]`。

| 源码 | 精确公开commit |
| --- | --- |
| workspace | `c4466aa48832526c420c726ece2d98f87b12c35c` |
| core-go | `0787b9f663c4f11ab713e2e421554a23c421fac8` |
| mobile | `01dadefb37e22d3a3ccebe4ac5ed26b53a3a4661` |
| server | `f5adbed146e728a47c15b755bdc26e29eea6bc46` |
| protocol | `fe67023bf917faa895fabcc439c40c82ad0a8e1a` |

候选覆盖：core-go的workflow.go、v3_test.go、androidfixture/main.go、crosscontroller/main.go、genericcontroller/main.go；mobile的NativeBridgePlugin.kt、native_workflow_adapter.dart、NativeGenericIntegrationTest.kt、NativeGenericTestSocket.kt、native-generic-test.py。每文件精确哈希保留于ignored manifest，不把整个当前working tree称为已测试。

- Source manifest SHA256：`17153ce7ce85992b2107f5e290c8c12f91228cfada0a5a18b5a0bb18c66bad97`。
- 正常AAR SHA256：`c478fe40c227a12469e586e0fd7adc43290ef4c497121abf01eba796f7ababd2`。
- 默认cert3 Mac CLI SHA256：`e141e9ee49db8969071956604265eea216860c645a1e26ccb80d443ed80fb02a`。
- 独立fixture APK SHA256：`250a774c4b10cb4b53a069c84d4e29550240c661560ffa212e053d153bc07428`。
- 独立test APK SHA256：`354e744136d74e40856f267f60c780453a14575191665ad475abff7ae8a2f55f`。

Go archive构建明确`-buildvcs=false -trimpath`，不冒充有VCS的clean commit产物；CLI及rootA helper加固定`harmonia_boringssl`。固定Go1.26.4、gomobile/gobind `v0.0.0-20260908204917-8b95e45f8d3e`、Flutter3.47.6、Java17、NDK28.2.13676358、BoringSSL `fab96f87245d7c6b941515201843665122650b88`。compileSdk36，实际Android14/API34 arm64隔离AVD。

## 实际结果

正常AAR、默认3 CLI、两个host controller、HTTPS fixture、Kotlin主/test APK实际构建通过。明确快照native标签桥race1.456秒、controller1.465秒；非UI Dart adapter analyze0.8秒无问题。此处没有声明后续其它Go草稿或整个当前Go树通过。

新focused `NativeGenericIntegrationTest` **1/1 PASS，52.072秒，19次系统设备密码CryptoObject提示、两controller exit0**。本轮没有取消认证场景，历史取消证据另算。

1. Host Go合成根A完成真实注册/邮件验证/完整恢复码重输初始化，建立X/Y；根A只在测试进程持钥，不是Android认证成功证据。
2. Android B通过cert3完整PAKE/双签获Y-only Admin。最后Applied保存#4故意失败：PENDING无data、Info accepted-not-applied/trustedfalse、View关闭；销毁临时对象后用原receipt/id Resume，最后保存成功才出只含Y的已验view。
3. B对X的写、轮换、批准均拒绝；拒绝批准未产生POST。B轮换Y，重复原id不增加checkpoint，再用新钥写Y合成值。
4. B批准新Mac CLI C的有限一小时RW Y-only。Controller版本3路径不传CLI版本flag，实际使用正式CLI默认3；服务器v2批准counter为0。
5. 真服务器接受B批准后合成502：原生PENDING、原选择Info、View/cancel gate拒绝；C实际双签complete→持钥boot→验签Pull/HPKE→隔离provider导出→rw put；daemon仍活着时X activation/put拒绝，export不含X变量。
6. B新对象Retry原id核验complete，批准counter不增；B验签Pull确认C的Y写入；Logout删除自己的key/state/alias。

首次fixture运行13.476秒在Resume成功后因测试期望`admin`而Go业务View枚举为`Admin`失败；轮换/C当时未跑。已保留失败日志与第一版源/产物manifest，只修正该断言和明确来源权限错误映射，正常重建AAR/APK后得到上述完整通过结果。未放宽信任、认证、端点或授权。

## 复现与清理

导出指定公开commit后，按README固定任务构建BoringSSL/工具链；ignored公共库缓存可显式复用，Node依赖须来自锁文件。归档不含Gradle wrapper与本机配置；固定官方Flutter build会生成wrapper，SDK/Flutter路径显式配置，不读取旧debugkey。只为合成fixture设置独立Android用户目录与包名。

在导出目录core-go下编译`.build/mobilebridge/{androidfixture,genericcontroller,crosscontroller,crossfixture-harmonia}`；CLI和genericcontroller用`-tags harmonia_boringssl -buildvcs=false -trimpath`，另两个`-buildvcs=false -trimpath`。在mobile下`mise run go-native-build`；通过固定Flutter bootstrap wrapper后，Gradle用`-PharmoniaNativeFixture=true :app:assembleDebug :app:assembleDebugAndroidTest`。启动`androidfixture --workspace <导出目录> --output <mobile/build/native/generic-fixture> --port 4443`，显式合法CA证书链/hostname验证保持开启。独立合成AVD装两fixture APK并设置本轮测试PIN，然后`HARMONIA_TEST_SERIAL=emulator-5580 mise run test-native-generic`（或快照`python3 tool/native-generic-test.py --serial emulator-5580`）。短码只经匿名pipe/本机test socket内存，不经runner参数、adb shell文本、HTTP或磁盘。

Driver只读本轮固定instrumentation tag；finally清自己的controller/forward。调用者还须finally清本轮PIN/fixture包/服务，保留原preview与AVD。实际终轮：noBackup测试文件为空、PIN清除、两fixture包卸载Success、CLI目录/进程0、forward空、HTTPS38160 exit0且4443连接拒绝；preview仍安装、API34 AVD57725继续运行，无reset/wipe。原始源/产物manifest、测试和cleanup记录只在`core-go/.build/native-v3-snapshot/`，未公开二进制、测试钥或凭据。

受限恢复旧Ed控制私钥只能进程内；独立registry骨架的TTL/binding/busy/logout/dispose测试不是Android恢复实现。Recovery typed cert4、native session lease接线、完整Flutter消费者流程、iOS、真机强生物/硬件证明仍未接通，不据此打开整体ready。
