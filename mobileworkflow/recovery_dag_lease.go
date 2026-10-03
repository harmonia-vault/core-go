package mobileworkflow

import (
	"context"
	"errors"
	"sync"

	"github.com/harmonia-vault/core-go/syncclient"
)

// 闲置 port 不保留任何 Workflow/provider。回调期间持 RLock，detach 必须排空。
type dagOwnerPort struct {
	mu     sync.RWMutex
	target *dagOwnerTarget
}
type dagOwnerTarget struct {
	entry                *dagOwnerEntry
	ctx                  context.Context
	journal              *syncclient.CheckedDAGJournal
	preparation          syncclient.DAGTransitionPreparationStore
	recoveredPreparation syncclient.DAGRecoveredPreparationStore
}

func (p *dagOwnerPort) attach(t *dagOwnerTarget) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.target != nil || t == nil || t.entry == nil || t.journal == nil || t.ctx == nil || t.ctx.Err() != nil || t.entry.retired.Load() {
		return ErrDAGOwnerMissing
	}
	p.target = t
	return nil
}
func (p *dagOwnerPort) detach(t *dagOwnerTarget) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.target != t {
		return ErrDAGOwnerMissing
	}
	p.target = nil
	return nil
}
func (p *dagOwnerPort) active() (*dagOwnerTarget, error) {
	t := p.target
	if t == nil || t.entry.retired.Load() {
		return nil, ErrDAGOwnerMissing
	}
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	return t, nil
}
func (p *dagOwnerPort) OwnerAlive() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	t, err := p.active()
	if err != nil {
		return err
	}
	if err = t.journal.OwnerAlive(); err != nil {
		t.entry.invalidate()
	}
	return err
}
func (p *dagOwnerPort) Load() (syncclient.ProtectedDAGOperation, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	t, err := p.active()
	if err != nil {
		return syncclient.ProtectedDAGOperation{}, err
	}
	original, err := t.journal.Load()
	// 不存在是初次受限会话的有效状态，其他错误立即撤销 lease。
	if err != nil && !errors.Is(err, errDAGJournalAbsent) {
		t.entry.invalidate()
	}
	return original, err
}
func (p *dagOwnerPort) Save(original syncclient.ProtectedDAGOperation) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	t, err := p.active()
	if err != nil {
		return err
	}
	if err = t.journal.Save(original); err != nil {
		t.entry.invalidate()
	}
	return err
}

type dagOwnerIdentity struct {
	Binding                                syncclient.DAGJournalBinding
	DeviceID, Signing, Receiving, Snapshot string
}

func (w *Workflow) attachDAGOwner(cancel context.CancelFunc) (dagOwnerIdentity, error) {
	return w.attachDAGOwnerState(cancel, false)
}
func (w *Workflow) attachDAGOwnerState(cancel context.CancelFunc, allowPending bool) (dagOwnerIdentity, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dagQueryCancel != nil || w.dagOwnerCancel != nil {
		return dagOwnerIdentity{}, ErrDAGQueryBusy
	}
	b, err := w.dagBindingLocked()
	if err != nil {
		return dagOwnerIdentity{}, err
	}
	// B1 只安装全新只读 owner；sealed 原包必须走 S2a，不可提升 fresh query。
	if (w.state.RecoveryDAGPreparation != nil || w.state.RecoveryDAGRecoveredPreparation != nil) && !allowPending {
		return dagOwnerIdentity{}, ErrDAGPreparationInterrupted
	}
	if w.state.RecoveryDAG != nil && !allowPending {
		return dagOwnerIdentity{}, ErrDAGOwnerBinding
	}
	if err := w.validateDAGStateLocked(); err != nil {
		return dagOwnerIdentity{}, err
	}
	w.dagOwnerCancel = cancel
	return dagOwnerIdentity{b, w.state.DeviceID, w.state.SigningPublicKey, w.state.ReceivingPublicKey, w.protectedSHA256}, nil
}
func (w *Workflow) detachDAGOwner() {
	w.mu.Lock()
	w.dagOwnerCancel = nil
	w.mu.Unlock()
}

func (p *dagOwnerPort) LoadTransitionPreparation() (syncclient.DAGTransitionPreparation, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	t, err := p.active()
	if err != nil {
		return syncclient.DAGTransitionPreparation{}, err
	}
	if t.preparation == nil {
		return syncclient.DAGTransitionPreparation{}, ErrDAGProtectedState
	}
	value, err := t.preparation.LoadTransitionPreparation()
	if err != nil && !errors.Is(err, errDAGJournalAbsent) {
		t.entry.invalidate()
	}
	return value, err
}
func (p *dagOwnerPort) SaveTransitionPreparation(value syncclient.DAGTransitionPreparation) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	t, err := p.active()
	if err != nil {
		return err
	}
	if t.preparation == nil {
		return ErrDAGProtectedState
	}
	if err = t.preparation.SaveTransitionPreparation(value); err != nil {
		t.entry.invalidate()
	}
	return err
}

func (p *dagOwnerPort) LoadRecoveredPreparation() (syncclient.DAGRecoveredPreparation, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	t, e := p.active()
	if e != nil {
		return syncclient.DAGRecoveredPreparation{}, e
	}
	if t.recoveredPreparation == nil {
		return syncclient.DAGRecoveredPreparation{}, ErrDAGProtectedState
	}
	v, e := t.recoveredPreparation.LoadRecoveredPreparation()
	if e != nil && !errors.Is(e, errDAGJournalAbsent) {
		t.entry.invalidate()
	}
	return v, e
}
func (p *dagOwnerPort) SaveRecoveredPreparation(v syncclient.DAGRecoveredPreparation) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	t, e := p.active()
	if e != nil {
		return e
	}
	if t.recoveredPreparation == nil {
		return ErrDAGProtectedState
	}
	if e = t.recoveredPreparation.SaveRecoveredPreparation(v); e != nil {
		t.entry.invalidate()
	}
	return e
}
