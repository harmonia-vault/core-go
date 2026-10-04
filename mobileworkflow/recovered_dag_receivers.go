package mobileworkflow

import (
	"context"
	"errors"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 保存完整已验控制而非裸 map；冷启动重新验原 pin、身份与所有历史签权。
// 遗漏/none/过期行均不能清空以前已见的 GG/hash；普通 Management 不可提升来源。
type dagReceiverBounds struct {
	sequence map[string]uint64
	subjects map[string]map[string]managementBound
}

func newDAGReceiverBounds() *dagReceiverBounds {
	return &dagReceiverBounds{sequence: map[string]uint64{}, subjects: map[string]map[string]managementBound{}}
}

// 调用方必须先用成熟验证器复验 control；此处只比较已保护的下界。
func (b *dagReceiverBounds) remember(control syncclient.ManagementControl) error {
	if control.Sequence < b.sequence[control.EnvironmentID] {
		return syncclient.ErrGrantUpdateConflict
	}
	prior := b.subjects[control.EnvironmentID]
	next := clone(prior)
	if next == nil {
		next = map[string]managementBound{}
	}
	for _, row := range control.Subjects {
		generation, e := strconv.ParseUint(row.HighestGrantGeneration, 10, 64)
		if e != nil || strconv.FormatUint(generation, 10) != row.HighestGrantGeneration || generation < prior[row.DeviceID].Generation {
			return syncclient.ErrGrantUpdateConflict
		}
		if row.CurrentGrant == nil {
			if generation != 0 {
				return syncclient.ErrGrantUpdateConflict
			}
			continue
		}
		fingerprint, e := syncclient.GrantContentHash(*row.CurrentGrant)
		if e != nil || generation == 0 || generation == prior[row.DeviceID].Generation && fingerprint != prior[row.DeviceID].Fingerprint {
			return syncclient.ErrGrantUpdateConflict
		}
		next[row.DeviceID] = managementBound{Generation: generation, Fingerprint: fingerprint}
	}
	b.subjects[control.EnvironmentID] = next
	b.sequence[control.EnvironmentID] = control.Sequence
	return nil
}

func (w *Workflow) verifyDAGReceiverHistory(c *syncclient.Client) (*dagReceiverBounds, error) {
	b := newDAGReceiverBounds()
	j := w.state.DAGEnvironments
	if j == nil {
		return b, nil
	}
	for _, control := range j.ReceiverControls {
		proof, e := c.VerifyManagementControl(control, true)
		if e != nil {
			return nil, e
		}
		if _, ok := proof.(*cryptox.VerifiedRecoveryDAG); !ok {
			return nil, ErrDAGProtectedState
		}
		if e = b.remember(control); e != nil {
			return nil, e
		}
	}
	return b, nil
}

// 同一 seq/KV 的有效 receiver 集必须逐签包精确相同。历史复验允许原已封存
// receiver 后来到期；这不授予当前轮换/重交权限，实时入口始终 historical=false。
func matchDAGReceivers(control syncclient.EnvironmentControlView, management syncclient.ManagementControl, now int64, historical bool) error {
	if control.Sequence != management.Sequence {
		return syncclient.ErrWriteConflict
	}
	receivers := map[string]cryptox.SignedGrantWire{}
	for _, g := range control.Grants {
		if g.Grant.EnvironmentID != management.EnvironmentID || g.Grant.KeyVersion != management.KeyVersion || receivers[g.Grant.SubjectDeviceID].Grant.SubjectDeviceID != "" {
			return syncclient.ErrWriteConflict
		}
		receivers[g.Grant.SubjectDeviceID] = g
	}
	for _, row := range management.Subjects {
		if row.CurrentGrant == nil {
			continue
		}
		g := *row.CurrentGrant
		expires, e := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
		if e != nil {
			return cryptox.ErrInvalidWire
		}
		eligible := (g.Grant.Role == "ro" || g.Grant.Role == "rw" || g.Grant.Role == "admin") && g.Grant.KeyVersion == management.KeyVersion
		active := eligible && (expires == 0 || expires > now)
		prior, present := receivers[row.DeviceID]
		if present && eligible && (active || historical) {
			if !sameJSONValue(prior, g) {
				return syncclient.ErrWriteConflict
			}
			delete(receivers, row.DeviceID)
		} else if active {
			return syncclient.ErrWriteConflict
		}
	}
	if len(receivers) != 0 {
		return syncclient.ErrWriteConflict
	}
	return nil
}

func (w *Workflow) commitDAGReceiverControl(management syncclient.ManagementControl, commit *dagActiveWriteLog) error {
	j := w.state.DAGEnvironments
	if j == nil || commit == nil {
		return ErrDAGProtectedState
	}
	b, e := w.verifyDAGReceiverHistory(w.client)
	if e != nil {
		return e
	}
	if e = b.remember(management); e != nil {
		return e
	}
	for _, prior := range j.ReceiverControls {
		if sameJSONValue(prior, management) {
			return nil // 已密封相同证据，不重复占预算。
		}
	}
	if len(j.ReceiverControls) >= 32 {
		return receiverPersistenceFailure(commit, syncclient.ErrWriteJournal) // 不驱逐旧下界以腾空预算。
	}
	j.ReceiverControls = append(j.ReceiverControls, clone(management))
	// 已验 higher/none 先落盘。后面的集合不匹配、权限错误都不能遗忘下界。
	if e = commit.commitCandidate(); e != nil {
		return receiverPersistenceFailure(commit, e)
	}
	return nil
}

// 已验新下界无法持久时仅能清确切 captured 旧版本。native 槽已推进/检查未知
// 只退休旧 handle，绝不把 RAM hash 相同当成删除新 scope 的依据。
func receiverPersistenceFailure(commit *dagActiveWriteLog, cause error) error {
	o := commit.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if commit.sameOwnerLocked() {
		exact := o.checkNativeState != nil && o.checkNativeState(commit.hash) == nil
		o.failDAGPersistenceLocked()
		if exact {
			commit.terminalCause = errors.Join(ErrDAGAuthorizationNotPersisted, cause)
			return commit.terminalCause
		}
	}
	return errors.Join(ErrDAGProtectedState, cause)
}

func (w *Workflow) verifyAndCommitDAGReceivers(ctx context.Context, control syncclient.EnvironmentControlView, environment string, commit *dagActiveWriteLog, originals ...syncclient.EnvironmentControlView) error {
	management, e := w.client.ManagementControl(ctx, environment)
	if e != nil {
		return e
	}
	if e = w.commitDAGReceiverControl(management, commit); e != nil {
		return e
	}
	if e = matchDAGReceivers(control, management, w.now().Unix(), false); e != nil {
		return e
	}
	for _, original := range originals {
		if e = matchDAGReceivers(original, management, w.now().Unix(), false); e != nil {
			return e
		}
	}
	return nil
}
