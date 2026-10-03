package mobileworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrDAGQueryBusy = errors.New("mobile DAG original query already active")
var ErrDAGOriginalRequired = errors.New("mobile DAG sealed original operation required")

// 仅 Go 高层结果，不接 native ABI；observation 不覆盖 Pending 的持久接受下界。
// 查询时未接受不是 terminal/abandoned；任何结果都不授予设备信任。
type RecoveryDAGQueryResult struct {
	Version          int                    `json:"version"`
	Profile          string                 `json:"profile"`
	Pending          RecoveryDAGPendingInfo `json:"pending"`
	Observation      string                 `json:"observation"`
	Confirmation     string                 `json:"confirmation"`
	RotationRequired bool                   `json:"rotationRequired"`
	TrustedDevice    bool                   `json:"trustedDevice"`
}

func emptyDAGQueryResult() RecoveryDAGQueryResult {
	return RecoveryDAGQueryResult{Version: 1, Profile: cryptox.RecoveryDAGCapability, Observation: "unknown", Confirmation: "none", RotationRequired: true}
}

// 单次 port 持有的 Workflow 引用只在此操作内有效。detach 等在途 callback
// 退出；Cancel 只取消 context，不能在 session/Save 锁内同步 detach 或 Close。
type dagQueryPort struct {
	mu      sync.RWMutex
	ctx     context.Context
	journal *syncclient.CheckedDAGJournal
}

func (p *dagQueryPort) detach() { p.mu.Lock(); p.journal = nil; p.mu.Unlock() }
func (p *dagQueryPort) alive() error {
	if p.journal == nil {
		return ErrClosed
	}
	return p.ctx.Err()
}
func (p *dagQueryPort) OwnerAlive() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.alive(); err != nil {
		return err
	}
	return p.journal.OwnerAlive()
}
func (p *dagQueryPort) Load() (syncclient.ProtectedDAGOperation, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.alive(); err != nil {
		return syncclient.ProtectedDAGOperation{}, err
	}
	return p.journal.Load()
}
func (p *dagQueryPort) Save(original syncclient.ProtectedDAGOperation) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.alive(); err != nil {
		return err
	}
	return p.journal.Save(original)
}

func sameDAGQueryOriginal(a, b syncclient.ProtectedDAGOperation) bool {
	a.Attempted, b.Attempted = false, false
	a.AcceptedSequence, b.AcceptedSequence = 0, 0
	a.Applied, b.Applied = false, false
	x, ex := json.Marshal(a)
	y, ey := json.Marshal(b)
	return ex == nil && ey == nil && bytes.Equal(x, y)
}

// QueryRecoveryDAGOriginal 只对已保护的原包创建本次新受限会话；完整当前码
// 不落盘、不自动试旧/新码。没有新业务 nonce、原包 POST、重新签名或新 ID。
// 方法不能持 w.mu 调 session，因为 journal callback 需要同一个 Workflow 锁。
func (w *Workflow) QueryRecoveryDAGOriginal(parent context.Context, completeCurrentCode []byte) (result RecoveryDAGQueryResult, err error) {
	result = emptyDAGQueryResult()
	defer clear(completeCurrentCode)
	if parent == nil || len(completeCurrentCode) == 0 || len(completeCurrentCode) > 512 {
		return result, ErrDAGOriginalRequired
	}
	if err = parent.Err(); err != nil {
		return result, err
	}
	seed, err := cryptox.DecodeRecoveryCode(string(completeCurrentCode))
	clear(seed)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	w.mu.Lock()
	if w.dagQueryCancel != nil || w.dagOwnerCancel != nil {
		w.mu.Unlock()
		cancel()
		return result, ErrDAGQueryBusy
	}
	binding, err := w.dagBindingLocked()
	if err == nil && w.state.RecoveryDAG == nil {
		err = ErrDAGOriginalRequired
	}
	if err != nil {
		w.mu.Unlock()
		cancel()
		return result, err
	}
	w.dagQueryCancel = cancel
	httpClient, now := w.http, w.now
	w.mu.Unlock()
	defer func() {
		cancel()
		w.mu.Lock()
		w.dagQueryCancel = nil
		w.mu.Unlock()
	}()
	journal, err := w.newRecoveryDAGJournal()
	if err != nil {
		return result, err
	}
	port := &dagQueryPort{ctx: ctx, journal: journal}
	defer port.detach()
	original, err := port.Load()
	if err != nil {
		return result, err
	}
	result.Pending, err = w.RecoveryDAGPendingInfo()
	if err != nil {
		return result, err
	}
	// Pin 来自已认证的原包，不从本次服务器目录重新选择。
	session, err := syncclient.OpenDAGRecoverySession(ctx, syncclient.DAGRecoveryConfig{Endpoint: binding.Endpoint, HTTPClient: httpClient, AccountID: binding.AccountID, AccountGeneration: binding.AccountGeneration, Pin: &original.Pin, Now: now, Journal: port}, string(completeCurrentCode))
	if err != nil {
		return result, err
	}
	defer session.Close() // 在所有 session 方法解锁后，且在 port.detach 前。
	info, err := session.Info()
	if err != nil || !info.RotationRequired || info.TrustedDevice {
		return result, errors.Join(syncclient.ErrDAGRecoveryState, err)
	}
	receipt, err := session.QueryOriginalOperation(ctx, original)
	if err != nil {
		return result, err
	}
	if receipt.Accepted {
		result.Observation, result.Confirmation = "accepted", "receipt-observed"
		if _, err = session.ResolveOriginalOperation(ctx); err != nil {
			return result, err
		}
		result.Confirmation = "original-verified-and-saved"
	} else {
		result.Observation = "not-accepted-at-query"
	}
	info, err = session.Info()
	if err != nil || !info.RotationRequired || info.TrustedDevice {
		return emptyDAGQueryResult(), errors.Join(syncclient.ErrDAGRecoveryState, err)
	}
	current, err := port.Load()
	if err != nil || !sameDAGQueryOriginal(original, current) {
		return emptyDAGQueryResult(), errors.Join(ErrDAGProtectedState, err)
	}
	result.Pending, err = w.RecoveryDAGPendingInfo()
	if err != nil {
		return emptyDAGQueryResult(), err
	}
	if result.Pending.OperationID != current.OperationID || result.Pending.ContentHash != current.ContentHash || result.Pending.AcceptedSequence != current.AcceptedSequence || result.Pending.OriginalApplied != current.Applied {
		return emptyDAGQueryResult(), ErrDAGProtectedState
	}
	if err = port.OwnerAlive(); err != nil {
		return emptyDAGQueryResult(), err
	}
	if err = ctx.Err(); err != nil {
		return emptyDAGQueryResult(), err
	}
	return result, nil
}
