# 服务可用的本地加密状态

`localkeys` 是独立的机器保护与状态存储基础。它不读取系统 Keychain，不读取真实环境，不进行登录、配对或设备授权，不把登录成功当可信设备。正式 POSIX daemon 由可信入网控制器验证双签回执与授权后，才能使用该目录中的设备钥进行持钥 boot 和同步；无已完成 context 时只提供恢复/IPC，不联网。Windows 正式 daemon 仍关闭。

## 接口与状态所有权

```go
store, err := localkeys.OpenEncryptedStateStore(localkeys.Config{
    Directory: canonicalPrivateDirectory,
    UserID: currentLocalUserID,
})
// 后台服务持有 store 的独占锁；CLI 通过受身份校验的 IPC 请求操作。
engine, err := localstate.New(store)
```

目录必须明确、绝对且不经过任何符号链接，父目录预先存在。macOS 的 `/var` 和 `/tmp` 是系统链接，测试显式使用规范化后的临时路径，服务建议使用 `/Library/Application Support/Harmonia/<UID>`。Unix 只接受当前真实/有效 UID 一致的非 root 用户；不会为了读取另一个用户的钥匙自动提权。

`StateStore` 实现 `Load/Save/Close`，只打开加密文件，不导入或迁移现有明文 fixture。`Synthetic` 状态会被拒绝。`Vault()` 给后台可信控制器使用，不能通过 IPC 暴露。固定 slot 为 `state-v1`、`device-v1`、`session-v1`、`trust-v1`、`provider-v1` 、`windows-originals-v1` 与 `writes-v1`，不接受任意文件名或路径。保存的设备材料是独立 Ed25519 seed 与 X25519 private key，公钥必须与私钥匹配；保存这些材料本身不会授予设备权限。登录 session 只记录 HTTPS 地址、账号 generation、token 与到期元数据，不保存密码派生凭据。

`SaveTrustContext/LoadTrustContext` 记录 HTTPS endpoint、账号 generation、设备双公钥、管理设备公钥、配对 profile 和入网回执。两端公钥必须与同 Vault 的独立 DeviceKeys 匹配；session 若存在，其 endpoint/账号/generation 也必须匹配。`Accepted=false` 的回执可在结果未知时重启后查询状态，再显式升级为完成；此布尔值不是配对或签名验证，控制器仍必须验证证书、PAKE 和授权。存储层不自动信任 `EnrollmentCertificate`，只检查结构与大小。已有绑定不能静默更换账号 generation/设备/幂等 key，已完成状态不能倒退。带云数据的 StateStore 必须匹配同目录已完成的绑定，防止不同账号目录/缓存混用。

`platform.NewSecurePOSIXProvider` 将暂停、修订号、来源目标和 release 元数据放入 `provider-v1`；Windows 的安全 constructor 将原值及注册表类型放入 `windows-originals-v1`。shell 消费的唯一 `environment.sh` 必须为本地明文，沿用私密目录句柄、0600 文件、ACL/所有权与原子写检查；不能写任意文件或覆盖非工具文件，不读取/迁移旧明文 fixture 元数据。

退出账号时，控制器需要停止并等待旧 session 的所有在途同步，拒绝旧 epoch 结果，删除 device/session/trust slot，再按 key 恢复环境。用于恢复的 Originals 不能在成功恢复前删除。多个 slot 各自原子保存，尚未提供跨 slot 事务或正式账号切换编排。

## 机器保护与加密

每个目录生成独立随机 256-bit 机器钥。Unix 默认使用服务用户可读取、权限受保护的软件钥；这使服务在系统磁盘解锁后、无人登录时可以使用它。机器钥是软件材料，不是硬件常驻密钥，也不依赖登录后才解锁的用户 Keychain。复制整个目录到另一台相同 UID 的机器并不会被软件机制可靠阻止。

敏感 slot 使用成熟库的 XChaCha20-Poly1305、独立随机 192-bit nonce。关联数据固定绑定格式域、目标 UID/SID、实际所有者、机器钥 ID 与 slot。篡改密文、nonce、身份、钥 ID 或跨 slot 移动都拒绝。密码不会派生本地机器钥，不改动客户端 SHA256(password) 登录约定。机器钥遗失而旧密文仍存在时立即拒绝，不能偷偷生成新钥并呈现空 vault；损坏不覆盖旧文件。

Unix 使用目录句柄与 `openat/O_NOFOLLOW` 限定操作，检查 `0700` 目录、`0600` 普通文件、当前 UID 和单硬链接；拒绝扩展 ACL。macOS ACL 检查通过官方 SDK `sys/attr.h`、`sys/kauth.h` 定义的只读 `fgetattrlist` ABI，临时原生 ACL 负测已通过。机器钥、锁或目录加载后被换走/改宽权限，后续操作仍会拒绝。独占 `flock`、临时文件同步、原子替换和目录同步用于避免并发写丢失与部分文件。

Windows 候选使用 DPAPI machine scope 包装随机机器钥，并使用受保护 DACL 将目录/文件限定为实际运行身份、SYSTEM 与 Administrators。专用服务 SID 必须对应目标用户 SID 派生的 Harmonia 服务名称；不会默认使用 LocalSystem 运行。设置 machine scope 后，同机器用户一旦拿到可解密 blob 就可解密，因此 **DPAPI machine scope 不能替代文件 ACL 隔离**。[Microsoft DPAPI 文档](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)

管理员、已攻陷的同一用户/服务进程、root 或已解锁并可读取保护材料的系统仍可能获得明文。磁盘解锁要求不绕过。AEAD 防篡改不等于防止攻击者整体恢复一份旧的有效目录；外部防回滚计数或硬件见证未实现。关闭时只做可控制缓冲区的尽力清零，不能声称 Go 运行时里所有副本已抹除。

## 当前证据与门槛

- macOS：`go test ./localkeys -race -count=1 -v` 的 11 项主测试通过，包含实际临时 ACL、重启保留设备材料/session/state、独占锁、随机 nonce、9 种篡改、跨 slot 移动、钥丢失/损坏不重置、权限变宽、符号链接及硬链接拒绝；还覆盖待完成回执重启、绑定不一致拒绝与状态账号隔离。
- OrbStack Ubuntu ARM64：新建非 root 临时账号与 `env -i` 子进程内全部主测试通过，包含实际 `setfacl` ACL 负测；最新平台安全 provider 测试通过，缺 zsh 的子测试按预期跳过。
- Windows amd64：DPAPI/DACL/锁实现交叉编译通过；原生 DPAPI、专用服务 SID、ACL 继承与目录路径竞态、断电持久化均未在 Windows VM 运行，仍是发布门槛。
- 未部署、未安装宿主服务、未使用真实钥匙或真实 session。既有明文 fixture constructor 仍仅限合成测试。正式 daemon 必须使用安全 provider 与已验证的信任上下文；完成本地存储不等于完成开机授权、真实同步与原生系统服务验收。

此项目采用 MIT。
