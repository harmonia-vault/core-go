# App PIN 独立本地保护核心

这是未接入产品的独立 native-only 包。它不判断 Android 是否具有系统认证能力，不调用 Keystore，不建立云账号/设备信任，不签名云请求；当前 AAR、原生桥、Flutter UI 和真实能力开关未接此包。不得据此宣称 App PIN 或整套软件生产可用。

## 固定合同

PIN 为 ASCII 数字6–32位，设置须完整重输；不 trim/Unicode归一化。固定 Argon2id v1.3、65536KiB、3次、p1、32B输出，随机32B salt。它仅派生本地KEK，标准AES-256-GCM随机12B nonce包封随机32B localVaultKey，后者独立nonce/AAD包封72B `HARMKEY1` 设备材料。没有PIN明文/hash/快速验证器或PIN直接当云环境钥的路径。p1是明确移动串行配置，不能冒称逐项等同RFC的p4推荐。

AAD确定性绑定用途/profile/version、package/namespace/slot、规范HTTPS endpoint、mode=pin、独立CSPRNG16B小写hex AuthGeneration/KeyEpoch、精确Ed25519/X25519双pub、完整固定KDF参数及salt。设备解包后重新导出双pub核对，不从文件声明建立信任。严格解码拒重复/未知字段、非规范编码、跨slot/endpoint/mode/generation、减弱或超大KDF成本。

成熟实现仅使用Go标准AES-GCM、crypto/rand、Ed25519/X25519和已固定依赖 golang.org/x/crypto/argon2；无GoMod新增或自创密码学。参考[Go Argon2](https://pkg.go.dev/golang.org/x/crypto/argon2)及[RFC9106](https://www.rfc-editor.org/rfc/rfc9106.html)。

## Native API 与持久适配

- `CreateRecord(pin,confirmation,binding,material)` 仅返回密文Record和Revision1初始AttemptState。native必须先核客观无系统认证、明确setup、新slot，并把两者原子落盘/readback后才可使用；不能给旧设备缺失limiter调用“重新初始化”。
- `NewProvider(record,expectedBinding,store,retireOwner)` 只读原完整记录和现limiter。缺失/损坏/不匹配拒绝；expectedBinding来自固定native配置，不能来自Dart授权bool。
- `Provider.Unlock(ctx,pin,opHash)`：整次非阻塞原生slot锁 → Load/CAS完整状态 → charge持久保存 → 固定KDF/AEAD → 成功settle持久保存 → 成功Release → 返回本次私有lease。任何native保存/释放错误永久关闭该Provider、不发lease，可能已提交的结果不能回滚猜测。错误返回前同步调用幂等retireOwner，native应立即清Recovery registry/old owner。
- `Lease.Consume(ctx,exactBinding,opHash,nativeCallback)` 只成功进入一次callback。绑定provider实例/完整scope/完整本次opHash/私有CSPRNG32B nonce；最多30秒待消费且不超过原ctx截止。nonce/句柄/材料不返Dart，不提供rawKey或任意签名。callback故意不能gomobile绑定，只供私有native wrapper导入并关闭Go Device；不得保留/输出借用材料。结束擦可控缓冲；最初Unlock的ctx和Consume的ctx都保持权威，不能以新ctx忽略原取消，callback即使返回nil也不报成功。
- lease的JSON/Text/Gob序列化与反序列化拒绝，值/指针fmt只显示opaque提示。它不防同进程reflection/unsafe/内存dump；native caller仍是信任边界。

DurableStore必须实现 `Acquire()error / Release()error / Load()(AttemptState,error) / Commit(expectedRevision,next)error`。Acquire/Release对整个Load→charge→KDF→settle持有本slot的跨进程独占文件锁；同实例另有TryLock。CAS、完整性保护、AtomicFile、0600、fd.sync和精确readback不可缺，Release异常也不能发lease。需要AndroidKeyStore无用户认证HMAC key保护元数据时，它只是完整性key，不是用户认证；不可用应拒绝，不偷偷改为软件MAC。此包没有该Android适配或其实际证明。

attempt在猜测之前增加Total/Failures并存随机PendingAttempt；kill/cancel不撤回charge。成功解包也须先同步settle保存才能发lease；正确PIN而结算失败仍无材料/业务授权。第5次失败起30秒，后续按失败数加倍，上限10分钟。重建Provider按完整持久delay重新施加当前进程单调等待；不使用可改的墙钟作为解锁依据，进程重启只可能增加等待。原生应在冷却期保留该Provider/单调等待生命周期，不能每次点击重新构造导致完整等待反复开始。同进程拒旧Revision/Total以及同Revision改写，不能声称阻止root级完整旧文件快照复原。

Provider.Close使其不可再用并取消活动lease。成功业务消费结束不会仅因正常软件Device/Workflow.Close自动延长或恢复任何Recovery owner。身份/模式升级、forgotPIN、Logout、dispose和所有认证/保存失败必须由native清旧registry，不能依赖本包形成云授权。

## 必须由原生层实现的模式规则

当前系统认证的supported布尔不能作PIN资格。只有无设备凭据且明确无已配置强生物时才可设置PIN；系统cancel/fail/lockout/HW_UNAVAILABLE/安全更新/未知错误不得降级。已有SYSTEM模式失去能力只关闭或明确本地清理。PIN后来检测到系统可认证，进入UPGRADE_REQUIRED；PIN仅能辅助迁移，不可继续批准CLI/读写。升级须正确旧PIN+真实CryptoObject，完整新包原子保存/readback后切SYSTEM并删除PIN副本；取消/保存失败保留旧密文也不等于授权PIN业务。[Android认证状态](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager)。

忘PIN没有找回：明确本地logout关闭所有owner，优先销毁包封能力/清PIN/device/workflow/cache/journal/limiter及backup/new文件；清理失败继续锁。新PIN须新Ed/X/deviceID，重新账号登录仍不可信，必须真实再授权或正式恢复，不删云vault或假称撤销了云旧device。

Recovery旧Ed仍仅在typed进程owner，不进入PIN包/磁盘。每次PIN失败/ctx取消/持久错误/模式切换/forget必须退役旧owner；正确PIN lease只许可本次本地解包，不延长原TTL或重造owner。normal操作Close可detach，下一op仍需新PIN；kill后owner缺失须既定完整旧码恢复。

## 能力与擦除边界

PIN低熵，复制密文可离线猜测；Argon2只提高每次成本，软件计数不能阻止离线枚举，不能宣称6位PIN等同系统硬件限流。Keystore外层设备绑定可以另外实现，但不证明root/App进程被攻破后的计数不可回放。[Android Keystore边界](https://developer.android.com/privacy-and-security/keystore)。

只清包所有的PIN/KEK/vaultkey/material缓冲；Go GC、标准AES内部key schedule、库内部X25519副本及被攻破进程的任意副本不能保证硬擦。Argon2没有中途ctx中止接口，本包前后检查取消并拒发lease；native认证取消须同时关闭registry，不把哈希运行完毕冒称业务成功。

## 本机合成验证

`mise exec -- go test -race ./appsecurity -count=1 -v` 验真实固定Argon2/AES、错PIN/篡改/AAD、严格参数/重输、precharge/settle/Release错误、真实自建子进程在持久charge后kill/reopen和limiter丢失、whole-attempt互斥、单次消费竞争和取消/缓冲擦除。临时文件适配实际fd.Sync/rename/readback，互斥为Go mutex；没有冒称Android MAC/跨进程flock/CryptoObject/真机PIN验证。仅合成PIN和材料，不读宿主env。Android实际能力仍关闭。


冻结验证使用公开 core `5040921e1867578be291b985736811326ed8ae6d` 的独立源码归档，仅叠加此目录8文件，不包含其它工作树草稿。Go1.26.4 固定依赖：最终 `go test -race ./appsecurity -count=1 -v` 11主/4子全部PASS，24.636秒；`go vet ./appsecurity` PASS。真实子进程中断专项此前PASS3.089秒，原Unlock上下文专项PASS3.013秒。源码基础扫描与人工公开范围检查PASS；新包没有新增GoMod依赖，没有接任何AAR/系统能力/云信任入口。以上不包含Android Keystore、文件锁/MAC适配或App PIN实际手机测试，它们仍未跑。
