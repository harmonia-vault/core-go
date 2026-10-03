package mobilebridge

// OpenAtomicWorkflow 使用静态 AtomicSealedStateStore 参数；gomobile 会保留
// Check/CAS 外部代理方法。原 OpenWorkflow 的静态 SealedStateStore 代理不能
// 依靠运行时 assertion 升级。此入口本身不开放任何 DAG/Recovery 操作。
func (d *Device) OpenAtomicWorkflow(endpoint, namespace string, sealed, additionalCA []byte, store AtomicSealedStateStore) (*VaultWorkflow, error) {
	if store == nil {
		return nil, errInput
	}
	if err := store.CheckSealed(sealed); err != nil {
		return nil, err
	}
	workflow, err := d.OpenWorkflow(endpoint, namespace, sealed, additionalCA, store)
	if err != nil {
		return nil, err
	}
	if err = store.CheckSealed(sealed); err != nil {
		workflow.Close()
		return nil, err
	}
	return workflow, nil
}

// Invalidate 立即撤销本对象的后续操作和RAM lease，取消在途context，但不
// 同步Close恢复owner。native必须锁外调用，worker排空后Close/Clear完成清钥。
func (v *VaultWorkflow) Invalidate() {
	if v == nil {
		return
	}
	v.saveFailed.Store(true)
	v.invalidateRecoveryOwner()
	v.cancelOperation()
}

// Invalidate 不等待在途owner.Close；native不可因此省略最终Clear/Close。
func (r *RecoveryRegistry) Invalidate() { r.invalidate() }
