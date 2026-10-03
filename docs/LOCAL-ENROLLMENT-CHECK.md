# 只读本机入网检查

macOS 和 Linux 的安装器可以在后台停止时，以安装目标用户运行：

```sh
harmonia local-enrollment-check --local-directory '<规范既有目录>' --local-user '<当前非 root UID>'
```

命令只接受 `local-directory` 和 `local-user`，不接受服务器、CA、fixture、环境导入或服务参数。UID 必须与当前进程身份相同，目录必须为绝对规范路径；安装器需要先降权到目标 UID/GID，不能以 root 读取目标钥匙。Windows 入口尚未实现。

成功返回码为 0，并且标准输出只有：

```json
{"version":1,"localEnrollmentVerified":true}
```

该结果只证明已有本机材料可核验，不能证明服务器当前仍允许这个设备访问。设备可能已在服务端撤销、降权、重置或到期；正式后台启动仍须通过现有在线 Boot 流程逐次检查当前授权。结果不返回邮箱、服务器地址、设备 ID、变量、私钥或登录凭据。

检查使用现有 `OpenExistingEncryptedStateStore` 的目录 FD、禁止跟随链接、权限/所有者/ACL 和非阻塞独占锁保护。缺目录、机器钥或锁时直接失败，不创建或修复材料；已有 owner 持锁时返回忙，不向 daemon 发请求，也不启动 daemon。检查期间只打开和读取既有材料，不更新密文、环境片段、epoch 或检查点。

在同一个受保护 Vault 锁内，检查加载并规范化本地状态，拒绝 `AccountClosed`，加载既有入网上下文和设备钥匙，调用正式后台同一 `verifiedStoredContext(trust, keys, state.Cloud)`。该函数核验 v1–v5 已完成入网的账号/代际/设备公钥绑定、双方签名和相关授权；有缓存时同时重验来源账本。未知版本、待完成收据、坏签、错代际、缺失或损坏的必需账本都失败。尚未拉取缓存的合法已完成收据保留现有空缓存语义。

`LoadTrustContext` 内部还会读取既有登录 session slot 来核对身份绑定；检查不会将其中的 token 交给网络客户端或输出。命令没有构造 HTTP 客户端、同步 worker 或平台 provider。设备私钥和验签器临时材料在结束时清理；Vault 的 `Close` 成功、且上下文未取消后才输出成功。关闭失败会保留错误，不能作为安装器的可启动证明。

```sh
mise run test-local-enrollment-check
```

测试使用公开合成签名向量和独立临时加密 Vault；不读取宿主真实凭据或环境变量。向量验签不等于新 PAKE、硬件钥匙保护或系统服务验收。
