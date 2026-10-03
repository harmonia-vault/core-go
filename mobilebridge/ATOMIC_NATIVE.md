# 原生 typed atomic opener（候选）

本增量基于 core `6d8178ae3116e6eb9dc4c1a9197c885c6a7687b1`。它只保留已存在的 `AtomicSealedStateStore` 跨 gomobile 静态代理能力，不增加 DAG/Recovery 操作、裸签名或 Dart 句柄。

`Device.OpenAtomicWorkflow(endpoint, namespace, sealed, additionalCA, store AtomicSealedStateStore)` 在打开前及打开后调用 `CheckSealed`，复用原 `OpenWorkflow`。普通 `SaveSealed`、`CheckSealed(expected)`、`CompareAndSwapSealed(expected,next)` 必须在平台同槽位 owner 下执行；expected 是本次实际认证捕获的完整原密文，不能失败后重新读新密文重试旧请求。旧 Save-only opener 继续兼容，不能靠运行时 assertion 宣称 JNI/ObjC 代理自动具有 CAS。

`VaultWorkflow.Invalidate()` 设置不可恢复的保存失败 latch，撤销恢复 RAM lease 并取消在途 context；`RecoveryRegistry.Invalidate()` 撤销 registry lease。两者不等待 owner.Close。平台在保存 gate 外调用，worker 排空后必须 Clear/Close 完成最终清钥；不能拿 Invalidate 代替 Close 或复活 disposed 对象。原 Cancel/Clear 行为保持。

Go 定向 race 已通过：打开前后检查、真实 CAS 回调、失败检查不再写、callback barrier 中 Invalidate 立即返回、返回后 lease 失效、最终 Close 恰一次。Android arm64 两份 AAR已编译（正常 bridge 与单独 test helper），Java Check/CAS 签名已编译核对。Android 六项首轮在平台目录前置停止（6/6 FAIL），目标 JNI/provider 尚未验收；框架 parent 元数据探针随后实际 PASS；修正后六项4PASS/2FAIL，真实创建取消+重开通过，但两项JNI首次空状态callback因Java null/Kotlin非空签名NPE而仍未验收。后续仅修平台nullable签名并严格比较空expected，Go/两AAR不变；定向两项随后各1/1 PASS（JUnit各0.040秒），真实Go→JNI空expected严格比较/CAS及typed opener的Check/Logout Save已验证；同APK的其余四项没有重跑，不能合称同产物六项通过；iOS 生成头/实际 provider 由独立 owner 验证。不得把 Go assertion 或编译通过当作平台已支持 DAG。

最新公开 core `69bc7c77eac4f7320741a4986d8bd6f17bb33704` 独立整合检查：mobilebridge 与恢复 lease registry 共48项 race PASS（16.856秒）、vet PASS（3.674秒）、22个 consumer 包编译 PASS（2.609秒，测试执行数0）。首次沙箱拒绝临时 loopback 监听的环境 FAIL 保留；正常审批后复跑通过。此项未重新构建 AAR/XCFramework，不能代替当前 B2 的原生产品链验收。[根整合证据](evidence/atomic-native-root-result.json)。
