# 本片实际验证结果

唯一真实接口主链 joint03 非 race PASS：主项 142.86 秒，包 144.297 秒。实际 HTTPS Node/SQLite、成熟连续恢复→本机 Boot/P4/final native AES CAS→BoringSSL V5 PAKE 只读目标→限期 RW 与实际 HPKE 读写→有限 Admin→RO 拒写→none 后目标 cache 空；504 丢回应后原 ID 冷续办不重 POST；attempted 取消只返回原 pending；从未尝试取消退休 ID；最后 CAS 失败零 grant POST 且原 slot 字节不变。

操作含冷 Open 的实际耗时 1.885–14.901 秒。产品每 handle 30 秒、主链总 240 秒未改。该耗时仅本次桌面 Go 运行，不等于 Android 性能或系统认证结果。

直接安全负例 components02 单主项 race PASS 139.72 秒、包 141.349 秒：原来源先通过完整成熟验签；接受未 Applied 的 none 原包限制共享 receiver 下界，旧 GG 目录拒绝；cold New 保原包/接受标记且不提升 Applied；同 basis 接受序号精确拒绝；全 POST 为零，保护槽不变。components01 的三个不受测试去重影响的小主项 PASS，分别为实际 producer/submit callback 屏障、strict bridge DTO、精确 self 降权例外。只复验原失败 cold 单项，没有重跑旧 CRUD/变量矩阵。三个受影响包 vet PASS。

历史失败保留：components01 workflow 240.534 秒测试总预算 timeout，末尾正常 DAG 解析验签，无此前断言失败；joint01 95.896 秒测试错误断言 FAIL，生产 attempted cancel 实际 ok:false 且未取消；joint02 执行器 transport 中断，日志无终态，UNCONFIRMED，不算通过也不把它当已证明产品失败。没有用延长产品期限或降低权限验证消除失败。

原生 AES store 是 Go test adapter。Android Java ABI/AAR/系统 CryptoObject/SDK、Flutter 产品流程全部 UNRUN；能力默认关闭。完整产品尚有全设备撤销、manager reanchor/旧来源升级等独立必要缺口。本轮验证未执行 VM/服务/真实邮箱，也未修改宿主环境变量。公开记录不包含原始账号、凭据或本机路径。

验收采用分层：共享业务由 Go/Dart 单元测试覆盖，服务端往来由真实接口集成覆盖；手机只补原生认证、钥匙保护、生命周期及最短产品路径，不重复所有角色和期限组合。此前平台通过结果仅在相关源码与依赖未变时复用。
