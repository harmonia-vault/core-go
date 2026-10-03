# 封闭原生 DAG 分派

`ValidateDAGRecoveryCommand` 只做唯一字段/规范 HTTPS/码长度预检，不能授认证或信任。`VaultWorkflow.ExecuteDAGRecovery` 只供已强认证的 native 新 AtomicWorkflow 使用，不在 WorkflowProfile 中公布，不新增 MethodChannel。

完整 code 为独立 byte buffer；函数始终 clear caller Go 缓冲。native Kotlin 还须清自己的缓冲；Go/Kotlin 的 String 与 GC 不承诺物理清零。email/password 仅当次 LoginDAGAccountScope 使用，helper 只 CAS 保存 public scope。

每调用先 Check 原完整 captured 密文，私有 registry reserve/finish（最多一个在途），domain 全由成熟 mobileworkflow B1/B2 执行，后续再 Check 同次最新 CAS 基点。绝不读新的 expected 重试旧内容。Go error 时 registry 永久失效；先按成熟 B2 操作/typed error 白名单检查，401/403、代际/绑定、wire、权限、持久化和取消等永不 soft；只有明确 wrong reentry、already prepared 或原请求暂时未知，再经成熟 `RecoveryDAGOwnerInfo` 的重新精确核验成功才允许 soft metadata 表示原 owner 保留，不据 HTTP 字符串猜测。

`queryDAGRecoveryOriginal` 是冷原包查询，不把新受限 session 放入 B1 registry，不能升级/恢复旧 RAM owner。若本 registry 曾开 owner，须先明确 native 本地取消并建立新 epoch。prepare/journal 原 ID、hash、accepted/unknown、originalApplied 由成熟 Go 投影，sequence 字符串，所有 trustedDevice 为 false。

Login helper 在有 journal/preparation 时拒绝，不能借 login 重置恢复进度。同 Workflow CAS 后桥的 protectedSHA256、mature Workflow 的导出状态 SHA 和 native captured 密文必须一致；有限真实 HTTPS 合成测试覆盖同 scope 冷重开与 CAS 失败零恢复路由。该测试不等于真实服务器 DAG 认证或 Android 系统密码验收。

成熟依据：mobileworkflow/recovery_dag_transition.go 的 dagTransitionRetryable 只允许 seal 的 ErrDAGNewCodeMismatch、begin 的 ErrDAGCodeAlreadyPrepared，或 begin preparation / retry enrollment 的 typed temporary transport/408/429/5xx。runDAGTransition 非 soft 将错误交 r.finish；recovery_dag_owner.go 的 finish 标 retired 并 closeOwner。桥只保留操作+sentinel候选（硬401/403/绑定等先拒），不复制domain的408/429/5xx可重试规则；domain finish 后精确OwnerInfo仍是必要条件。桥的明确前置分类还避免 Login/metadata 错误在原 RAM仍活时被误投影。有限 typed 401/403/OwnerBinding 负例及504原retry正例覆盖此边界，没有新网络矩阵。
