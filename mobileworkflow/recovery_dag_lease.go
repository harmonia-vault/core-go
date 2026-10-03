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
	entry   *dagOwnerEntry
	ctx     context.Context
	journal *syncclient.CheckedDAGJournal
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
	if w.state.RecoveryDAG != nil {
		return dagOwnerIdentity{}, ErrDAGOwnerBinding
	}
	w.dagOwnerCancel = cancel
	return dagOwnerIdentity{b, w.state.DeviceID, w.state.SigningPublicKey, w.state.ReceivingPublicKey, w.protectedSHA256}, nil
}
func (w *Workflow) detachDAGOwner() {
	w.mu.Lock()
	w.dagOwnerCancel = nil
	w.mu.Unlock()
}
