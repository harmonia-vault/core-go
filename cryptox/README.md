# 加密与签名底座

这是实验性安全组件，不能据此宣称 Harmonia 已可用于生产。

客户端登录派生严格为 `SHA256(password)`，没有客户端盐、域或额外 KDF。该结果是可重放的密码等价凭据；不得写日志、缓存或充当 vault 密钥。

环境数据使用独立随机 256 位环境钥和 Go 官方 `golang.org/x/crypto/chacha20poly1305` 的 XChaCha20-Poly1305；每次加密生成随机 192 位 nonce。账号、账号代际、环境、密钥版本和变量名进入域分离 AAD。

环境钥封套使用 Go 1.26 标准库 `crypto/hpke`，套件为 RFC 9180 基础模式 DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305。封套上下文绑定账号代际、环境版本、接收用途、接收设备、授权或恢复代际及接收公钥。管理设备的独立 Ed25519 签名覆盖完整封套。标准库 HPKE 的基础模式本身不提供发送者身份认证。

`VerifyMutation` / `VerifyGrant` 只验证密码学签名。调用方必须从可信设备审批流程取得并固定公钥，逐次检查当前账号代际、角色、撤销和有效期，再验证授权链及持久化序号。服务器给出的陌生公钥不能直接成为信任根。RO 持有环境对称钥，能制造合法 AEAD 密文；是否可写由管理签名授权和设备签名共同决定。

恢复底座仅实现随机 256 位种子、完整 base32 编码、用途及账号/恢复代际分离的标准 HKDF-SHA256 派生和恢复 HPKE 封套。受限恢复会话、新码完整重输、一次 nonce 持钥证明、必要封套原子轮换和断网结果查询尚未由此组件完成。不能把拥有派生函数等同于已完成恢复流程。

`testdata/signatures-v1.json` 的种子、密码和明文都是公开合成测试数据；禁止用于真实凭据。对应公开协议向量在 protocol 仓库中保留同一份字节。测试包含 Go/Node 签名互操作、逐字段篡改、AEAD/HPKE 字节篡改、账号/环境/版本绑定、RFC 9180 A.2.1 已知答案和恢复用途分离。

运行：`mise run test`。完整协议见 [protocol](https://github.com/harmonia-vault/protocol)。已选择的成熟 SPAKE2 实现和手机平台钥匙保护仍是门槛，本包不提供绕过配对的生产入口。

来源：[Go HPKE 官方文档](https://pkg.go.dev/crypto/hpke)、[Go XChaCha 官方文档](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305)、[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)。
