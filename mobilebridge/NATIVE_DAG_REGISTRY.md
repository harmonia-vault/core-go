# 原生 DAG registry：A 分片

固定公开底座 core `67db4a7999d7827a7418d6ad4094ddd73d64145a`；本片仅 mobilebridge 生命周期/ABI，不修改 mobileworkflow、syncclient、cryptox 或服务端。本片没有 DAG 业务 dispatch、MethodChannel、profile/cap 开放，也不导出 owner/签名/钥匙/状态。B1/B2 Android 业务尚未运行。

`NewNativeDAGRegistry(namespace,slot,platformEpoch)` 只接受可信原生固定配置；正 int64 platformEpoch 与每操作的文件 owner epoch 不同。它只是范围，不是认证。每次应通过真实 CryptoObject 和 `OpenAtomicWorkflow` 创建新 Workflow，`AttachDAGRegistry` 再核完整 protected namespace、静态 Atomic provider、固定 endpoint/本机双公钥。账号/gen/SessionEpoch/snapshot 的真实业务绑定仍由成熟 B1/B2 typed 方法检查，A 尚未调用它们。

registry 不保存 Workflow、Device、材料或 store。正常 `VaultWorkflow.Close` 只解除当次 attachment；跨次 registry 不销毁。DAG registry 的 native Invalidate 永久拒绝新 lease，只取消自己的全部在途 context，不调用可能同步清 session 的 domain Clear/Close。worker 在业务/保存 callback 排空后调用 Close：先等全部私有操作记录结束，再 exactly-once domain Close。不得在 native gate 或 callback 内 Close；进程 death 自然丢失，不序列化/恢复 registry。

本片复用既有 `VaultWorkflow.Invalidate` 经 private `invalidateRecoveryOwner` 委托到新 registry；保存/Check/CAS 失败同样立即死票并取消 context。旧 cert4 registry 的行为保留。Cancel 增加 DAG 死票；正常 Close detach，保存失败 Close 在 worker 排空后关闭 DAG registry。没有改动 `workflow_atomic_native.go` 的静态 opener/旧 API。

私有 reserve/finish 仅为下一片封闭 typed dispatcher 使用，单 registry 一次操作、30秒 context，禁止公开任意 callback/importOwner/rawSign。B 分片仍需把每次该 context 与当次 Workflow cancel/typed方法完整接通，验证真实JNI与SDK认证，不可把本片空 registry 跨两个合成 Workflow 的组件测试当作真实私钥 owner跨认证实证。

本片定向6个 Go race测试覆盖scope/拒序列化、正常Close仅detach、替换device/namespace/save-only拒绝、Invalidate不等callback、保存失败先cancel再Close、取消全部私有context。受影响 mobilebridge+recoverysessions 全包最终54个通过事件，vet通过。首次新增test fixture类型名编译失败原始记录保留。Android arm64 AAR实际编译和生成Java签名通过；JNI运行、系统设备密码和业务HTTP均未执行。完整固定输入/源差分与产物在本片私有FREEZE记录，二进制不公开。
