package localkeys

import (
	"bytes"
	"errors"
	"github.com/harmonia-vault/core-go/localstate"
	"os"
)

// RecoveryDAGOwnerEpoch仅绑定原生owner的本机epoch，不授予恢复或设备信任。
func (v *Vault) RecoveryDAGOwnerEpoch(account string, generation uint64) (uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.recoveryDAGEpochLocked(account, generation)
}
func (v *Vault) recoveryDAGEpochLocked(account string, generation uint64) (uint64, error) {
	if !identityPattern.MatchString(account) || generation == 0 {
		return 0, ErrIdentity
	}
	raw, err := v.loadLocked("state-v1")
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer clear(raw)
	var state localstate.State
	if strictJSON(raw, &state) != nil || state.Version != 1 {
		return 0, ErrCorrupt
	}
	if state.Synthetic {
		return 0, ErrFixture
	}
	if state.AccountClosed || state.Cloud.AccountID != "" && (state.Cloud.AccountID != account || state.Cloud.AccountGeneration != generation) {
		return 0, ErrIdentity
	}
	return state.SessionEpoch, nil
}

// 检查epoch与写入在同一Vault锁内；logout tombstone已经提交后，旧RAM会话不能重新创建journal。
func (v *Vault) SaveRecoveryDAGJournal(account string, generation, epoch uint64, raw []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	current, err := v.recoveryDAGEpochLocked(account, generation)
	if err != nil {
		return err
	}
	if current != epoch {
		return ErrIdentity
	}
	return v.saveLocked("recovery-dag-v1", raw)
}
func (v *Vault) LoadRecoveryDAGJournal(account string, generation, epoch uint64) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	current, err := v.recoveryDAGEpochLocked(account, generation)
	if err != nil {
		return nil, err
	}
	if current != epoch {
		return nil, ErrIdentity
	}
	return v.loadLocked("recovery-dag-v1")
}

// CompareAndSwapRecoveryDAGJournal 在同一 Vault 锁内核 epoch、原字节与保存。
// 关闭账号即使已经删除 journal，也不能由旧 owner 重新创建。
func (v *Vault) CompareAndSwapRecoveryDAGJournal(account string, generation, epoch uint64, previous, next []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	current, err := v.recoveryDAGEpochLocked(account, generation)
	if err != nil {
		return err
	}
	if current != epoch {
		return ErrIdentity
	}
	raw, err := v.loadLocked("recovery-dag-v1")
	defer clear(raw)
	if errors.Is(err, os.ErrNotExist) {
		raw = nil
	} else if err != nil {
		return err
	}
	if (raw == nil) != (previous == nil) || !bytes.Equal(raw, previous) {
		return ErrCorrupt
	}
	return v.saveLocked("recovery-dag-v1", next)
}
