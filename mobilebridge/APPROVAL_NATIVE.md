# Android 首根批准 CLI 的原生切片

记录日期：2026-10-02 UTC。本切片是实验性 `first-root-issuer-proof-v1` / certificate v2，仅已经完整确认首次初始化的根手机批准初始环境；不代表 cert3、非根管理手机、新环境来源、恢复、iOS 或 Flutter 界面已经接通。整体 `realVaultReady=false` 保持不变。

## 调用与强认证边界

`VaultWorkflow.ExecuteApproval(command, shortCode []byte)` 是独立入口。command 为严格 flat JSON，包含 version、operation=approvePairing、固定 HTTPS endpoint、pairingId 和 selections。selections 是独立有界 JSON 字符串，要求 1–16 个不同环境，每项恰为 environmentId、role(ro/rw/admin)、expiresAt(规范 Unix 秒或明确的0)。重复字段、未知字段、数量/大小超限与非规范值拒绝；Root、证书、封套、来源证明或服务器签包没有输入字段。旧 approveDevice 与普通 Execute 无短码批准继续拒绝。

短码为独立八位数字字节，不写 JSON。Android executeApproval 的 MethodChannel 参数只有 command 和短码 ByteArray；Dart 不返回/持久化密码学材料。Kotlin 消费输入后清原缓冲，短暂副本只等候本次系统强认证，取消、不支持、BUSY、dispose、异常及结束均清理可控缓冲。Go 在入口结束时清可控短码；Go/JNI/托管运行时历史副本不能保证全部擦除。短码只进入固定 BoringSSL SPAKE2，不能发送服务器、存盘或日志。

每次 approve/retry/info/cancel 均重新 CryptoObject 系统认证并临时解包本机独立设备钥、解密独立 AES 状态。只有 approve 的局部 context 为120秒，其它操作仍30秒；这不延长服务器挑战。来源和授权由 Go 使用本地精确 InitialAuthorities、Root pin 与当前已验授权重新构造，缺来源的旧实验上下文拒绝审批，不重置账号。

prepared 与 attempted 都必须同步完成真实原生 AES/AtomicFile 保存，才允许批准 POST。approved 只代表管理者签包已接受；必须验新设备同一证书双签和完成序号并保存，才返回 complete。结果不明只允许 retryApproval 原 pairingId、approvalInfo 元数据或退出；普通 view/共享写入拒绝。cancelApproval 只可清未尝试 HTTP 的 prepared 记录，不能取消在途/unknown 或冒充服务器撤销。全部保护状态、登录/设备会话、封套/签包和钥匙不返回 Dart。

## 本机实测

固定 Go1.26.4、Flutter3.47.6、Java17、NDK28.2.13676358 / Clang19.0.1；BoringSSL fab96f87245d7c6b941515201843665122650b88。gomobile独立 binding module 版本及源码构建入口不变。compileSdk36；实际 Android14 API34 arm64，二者不同。

正常 AAR 的 NativePairingIntegrationTest 在当时编译的 CLI 基线（core-go c4dec971，v2默认；构建标记 working tree modified）完整 focused 通过59.074秒；mise入口复测通过58.733秒，各21次系统认证提示含1次取消，四个独立 compiled CLI 控制器均 exit0。旧12/12证据没有算作新路径测试。基线记录保存在ignored mobile/build/native/approval-focused-controller-final.txt。

- 手机真实 HTTPS 注册/捕获合成邮件验证→首次 root 双签初始化/完整码重输→合成变量。独立 Android 管理者与真实编译 macOS CLI，短码经匿名 stdout pipe 与 ADB localhost→localabstract 测试 socket，仅内存；无 runner 参数、adb shell 文本、HTTP、日志或磁盘短码。明确仅初始环境 rw、有限一小时期限。
- known批准→CLI v2双签完成→持钥 boot、验签/HPKE Pull→本次新私有目录/environment.sh 的 activate/export→真实 rw put；不 source、不安装服务、不触宿主环境。该通过基线编译时默认版本为2。新 CLI 默认已改3，当前 controller 明确传 --certificate-version 2，不能自动降级；新来源校验下的失败诊断与修正后单次 fresh 结果见下段。
- 服务器真实接受原 /pairings-v2/:id/approve 后把200换502：原生返回 unknown/PENDING，view与取消拒绝；CLI仍完成双签。原生重新创建保护会话后 retry 原id，核 complete/sequence，服务器approval计数不增。
- prepared保存与attempted保存分别在真实同步密封回调第3/5次注入失败，批准POST计数不增。前者保持此前已完成日志；后者保留prepared，可重新系统认证明确取消。未保存的 PAKE 临时状态不能恢复，也没有自动产生新ID或持久短码。
- 系统认证取消/BUSY 不开始PAKE、不改变原AES文件或HTTP批准计数。logout删除本轮钥、状态和Keystore槽；测试finally只清自身槽与文件。

Go mobilebridge/controller普通race、native-tag race、AAR与Kotlin main/test编译通过。工具与业务源码均不含真实秘密；UI/defaultgateway未改。真实强生物/硬件隔离、cert3/non-root/新环境审批、新Genesis恢复锚与恢复轮换原生验收仍未完成。

## 来源闭包兼容诊断与 fresh 验收

加入 origin-aware v2 后，显式选择2的两次复测55.248/54.702秒在第二候选verified Pull失败：daemon和IPC正常，公开status为0/0/0。原因是普通数据拉取未包含第一候选历史mutation的冻结授权和归档双签写入者身份来源。没有放宽客户端门槛；服务器补该控制证据闭包后，定向20/20通过。

2026-10-02 UTC，按父任务要求仅一次fresh focused，重建正常AAR、两个独立APK、当前CLI、合成PIN及新的HTTPS/临时SQLite夹具，完整1/1通过59.634秒，21次系统设备密码提示含1次取消，known/lost-response/prepared-save-failure/attempted-save-failure四个compiled CLI controller均exit0。两候选均实际双签入网、持钥boot、验签/HPKE Pull、隔离environment.sh激活/导出和rw put；accepted200换502后原生新对象retry同id确认complete且approval计数不增加。两同步保存失败无批准POST，prepared可认证后明确取消；auth取消/BUSY无文件/网络改变，Logout删除资料。本次全部分支运行，未借用旧12项或旧modified基线证据。

实际构建CLI元数据为Go1.26.4/darwin-arm64/harmonia_boringssl，core-go提交180139230bc778868b72cdda851dd589148af26a、vcs.modified=true；server基线4fe2cb897990574c22d138924dfe72d4c7472357、modified=true，mobile基线591d0814e6d7763c8cc2b52b35dea1a00290d4ac、modified=true。CLI SHA256为3e68359dadf04162638bf9d3ba631bd3f4c1acceb521cc813e9ca530f0603d37，正常AAR SHA256为78e26d50dd5fcb39647915b6ecaf853227cca22252b7c5646a3dba0fb695ed4f。准确构建元数据/Go文件集合哈希（含测试）在ignored core-go/.build/mobilebridge/approval-fresh-source.txt，APK哈希在mobile/build/native/approval-fresh-artifacts.txt。编译期间其它代理添加测试，之后还有新的Go来源/恢复门槛实现；本结果只覆盖上述实际编译产物，不声称后续working tree全部改动已运行。编译期间mobileworkflow生产初始化/批准API未变。

正常AAR、Kotlin main/test APK构建通过；runtime为Android14/API34 arm64，compileSdk36。原始单次fresh结果在ignored mobile/build/native/approval-focused-fresh-current.txt，构建日志approval-fresh-native-build.log/approval-fresh-android-build.log，清理记录approval-fresh-cleanup.txt。cert3/非根/新环境、Recovery process-only会话、新码轮换与Flutter入口均未在本切片运行，整体ready仍false。

## 复现与清理

必须显式选择可丢弃的合成 AVD，不得设置宿主或真实设备PIN。保留预览包；构建用 `-PharmoniaNativeFixture=true` 独立包名。仅新建 CLI 临时目录，规范短路径避免 /var 符号链接与Unixsocket长度，secure provider要求精确own/environment.sh，不能放宽目录/权限检查。

1. 在 core-go 通过 mise构建 host BoringSSL，再 `mise exec -- go build -tags harmonia_boringssl -trimpath -o .build/mobilebridge/crossfixture-harmonia ./cmd/harmonia`；`mise exec -- go build -trimpath -o .build/mobilebridge/crosscontroller ./mobilebridge/cmd/crosscontroller`。
2. mobile `mise run go-native-build`；android `mise exec -- env ANDROID_USER_HOME=<隔离测试目录> ./gradlew :app:assembleDebug :app:assembleDebugAndroidTest -PharmoniaNativeFixture=true`，签名钥只在该新测试目录，不读取旧debug/release钥。
3. core-go `mise exec -- go run ./mobilebridge/cmd/androidfixture --workspace <workspace> --output ../mobile/build/native/approval-fixture`。夹具自建临时SQLite、合法临时CA与SAN(127.0.0.1/10.0.2.2)，不关闭证书链或hostname校验；CA参数是公开证书，私钥只在夹具进程。
4. 只给隔离AVD设合成测试PIN24681357；安装ignored独立app-debug/app-debug-androidTest APK。mobile `HARMONIA_TEST_SERIAL=emulator-5580 mise run test-native-approval`。Python驱动要求emulator和ro.kernel.qemu=1，读取仅测试阶段tag，验证1项JUnit与四CLI控制器真实成功，故障不假报成功并关闭自己的forward/controller。
5. 即使失败也须清本次PIN、卸载nativefixture与nativefixture.test、停夹具。JUnit finally/退出只删本test alias/key/state；CLI新目录与process全部清；夹具停止关闭并删临时SQLite。保留原preview与AVD数据，不reset/wipe。

通过基线及最新失败兼容复测均已清：合成PIN已移除、两个fixture包卸载成功、test noBackup文件/alias删除、CLI新目录/进程数量0、局部forward无残留；HTTPS进程已结束且127.0.0.1:4443连接被拒绝，子Node按信号关闭临时SQLite并删其测试目录。preview仍安装、API34 AVD继续运行，未reset/wipe。忽略目录仅保留构建/公开CA/原始验收记录，APK/AAR不公开。上述实际编译产物的v2窄切片已通过；源码冻结待root审查，不自行提交或扩大ready。
