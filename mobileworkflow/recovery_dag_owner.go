package mobileworkflow

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

var (
	ErrDAGOwnerMissing  = errors.New("process-only DAG owner unavailable")
	ErrDAGOwnerBinding  = errors.New("DAG owner binding rejected")
	errDAGJournalAbsent = os.ErrNotExist
)

const dagOwnerMaxTTL = 5 * time.Minute

// 仅受信任 Go/native 调用；平台 epoch 必须由实际 provider 给出，不能来自 UI。
// B1 未接平台 ABI，本类型不代表一次系统认证已通过。
type DAGOwnerScope struct {
	Namespace, Slot string
	PlatformEpoch   uint64
}

func validDAGOwnerScope(s DAGOwnerScope) bool {
	return len(s.Namespace) > 0 && len(s.Namespace) <= 512 && len(s.Slot) > 0 && len(s.Slot) <= 128 && utf8.ValidString(s.Namespace) && utf8.ValidString(s.Slot) && !strings.ContainsAny(s.Namespace, "\x00\r\n\t") && !strings.ContainsAny(s.Slot, "/\\\x00\r\n\t")
}

type dagOwnerSession interface {
	Info() (syncclient.DAGRecoveryInfo, error)
	VerifiedBinding() (syncclient.DAGRecoveryBinding, error)
	Close()
}
type dagOwnerTimer interface{ Stop() bool }
type dagOwnerEntry struct {
	phase     string
	registry  *DAGRecoveryRegistry
	port      dagOwnerPort
	session   dagOwnerSession // 仅当前 busy 操作或 idle 的 exactly-once 清理使用
	identity  dagOwnerIdentity
	binding   syncclient.DAGRecoveryBinding
	deadline  time.Time
	lastWall  int64
	timer     dagOwnerTimer
	busy      bool
	cancel    context.CancelFunc
	retired   atomic.Bool
	closeOnce sync.Once
	closed    chan struct{}
}

func (e *dagOwnerEntry) invalidate() { e.registry.invalidate(e, false) }
func (e *dagOwnerEntry) closeOwner() {
	e.closeOnce.Do(func() {
		if e.session != nil {
			e.session.Close()
		}
		close(e.closed)
	})
}

// 独立 typed RAM registry；无安装外部 session/handle 或任意 operation callback API。
// B1 的 Open/Info/Clear/Close 保持只读；B2 仅经封闭 typed transition 方法换代。
type DAGRecoveryRegistry struct {
	mu       sync.Mutex
	scope    DAGOwnerScope
	current  *dagOwnerEntry
	disposed bool
	now      func() time.Time
	after    func(time.Duration, func()) dagOwnerTimer
}

func (*DAGRecoveryRegistry) String() string               { return "DAG recovery registry (process only)" }
func (*DAGRecoveryRegistry) GoString() string             { return "DAG recovery registry (process only)" }
func (*DAGRecoveryRegistry) MarshalJSON() ([]byte, error) { return nil, ErrDAGOwnerBinding }
func (*DAGRecoveryRegistry) UnmarshalJSON([]byte) error   { return ErrDAGOwnerBinding }
func (*DAGRecoveryRegistry) UnmarshalText([]byte) error   { return ErrDAGOwnerBinding }
func (*DAGRecoveryRegistry) MarshalText() ([]byte, error) { return nil, ErrDAGOwnerBinding }
func NewDAGRecoveryRegistry(scope DAGOwnerScope) (*DAGRecoveryRegistry, error) {
	return newDAGRecoveryRegistry(scope, time.Now, func(d time.Duration, fn func()) dagOwnerTimer { return time.AfterFunc(d, fn) })
}
func newDAGRecoveryRegistry(scope DAGOwnerScope, now func() time.Time, after func(time.Duration, func()) dagOwnerTimer) (*DAGRecoveryRegistry, error) {
	if !validDAGOwnerScope(scope) || now == nil || after == nil {
		return nil, ErrDAGOwnerBinding
	}
	return &DAGRecoveryRegistry{scope: scope, now: now, after: after}, nil
}
func (r *DAGRecoveryRegistry) invalidate(e *dagOwnerEntry, dispose bool) {
	r.mu.Lock()
	if dispose {
		r.disposed = true
	}
	if e == nil {
		e = r.current
	}
	if e == nil {
		r.mu.Unlock()
		return
	}
	e.retired.Store(true)
	if e.cancel != nil {
		e.cancel()
	}
	if e.timer != nil {
		e.timer.Stop()
	}
	idle := !e.busy
	r.mu.Unlock()
	// 业务锁内的 active cancel 不得同步 Close；busy 操作 finally 负责 drain 后清理。
	if idle {
		e.closeOwner()
	}
}
func (r *DAGRecoveryRegistry) Clear() { r.invalidate(nil, false) }
func (r *DAGRecoveryRegistry) Close() { r.invalidate(nil, true) }
func (r *DAGRecoveryRegistry) acquire(parent context.Context, scope DAGOwnerScope, opening bool) (*dagOwnerEntry, context.Context, error) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, ErrDAGOwnerMissing
	}
	r.mu.Lock()
	if r.disposed || r.now == nil || r.after == nil || !validDAGOwnerScope(scope) || scope != r.scope {
		r.mu.Unlock()
		return nil, nil, ErrDAGOwnerBinding
	}
	e := r.current
	now := r.now()
	if now.Unix() <= 0 {
		r.mu.Unlock()
		return nil, nil, ErrDAGOwnerBinding
	}
	if opening {
		if e != nil {
			if !e.retired.Load() || e.busy {
				r.mu.Unlock()
				return nil, nil, ErrDAGQueryBusy
			}
			select {
			case <-e.closed:
			default:
				r.mu.Unlock()
				return nil, nil, ErrDAGQueryBusy
			}
		}
		e = &dagOwnerEntry{registry: r, deadline: now.Add(dagOwnerMaxTTL), lastWall: now.Unix(), closed: make(chan struct{})}
		r.current = e
	} else if e == nil {
		r.mu.Unlock()
		return nil, nil, ErrDAGOwnerMissing
	}
	if e.retired.Load() || !now.Before(e.deadline) || now.Unix() < e.lastWall {
		r.mu.Unlock()
		r.invalidate(e, false)
		return nil, nil, ErrDAGOwnerMissing
	}
	if e.busy {
		r.mu.Unlock()
		return nil, nil, ErrDAGQueryBusy
	}
	e.lastWall = now.Unix()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	e.busy, e.cancel = true, cancel
	if opening {
		e.timer = r.after(e.deadline.Sub(now), e.invalidate)
	}
	r.mu.Unlock()
	return e, ctx, nil
}
func (r *DAGRecoveryRegistry) finish(e *dagOwnerEntry, ctx context.Context, err error) error {
	r.mu.Lock()
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	now := r.now()
	if e.retired.Load() || r.disposed || !now.Before(e.deadline) || now.Unix() < e.lastWall {
		err = errors.Join(err, ErrDAGOwnerMissing)
	}
	if err != nil {
		e.retired.Store(true)
		if e.timer != nil {
			e.timer.Stop()
		}
	}
	if e.cancel != nil {
		e.cancel()
	}
	e.cancel = nil
	e.busy = false
	retired := e.retired.Load()
	r.mu.Unlock()
	if retired {
		e.closeOwner()
	}
	return err
}
func (r *DAGRecoveryRegistry) pinDeadline(e *dagOwnerEntry, expires int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if e.retired.Load() || !e.busy || expires <= now.Unix() {
		return ErrDAGOwnerMissing
	}
	deadline := now.Add(time.Duration(expires-now.Unix()) * time.Second)
	if deadline.Before(e.deadline) {
		e.deadline = deadline
		e.timer.Stop()
		e.timer = r.after(e.deadline.Sub(now), e.invalidate)
	}
	return nil
}

// 每次调用创建独立 authenticated Workflow；只在当次 lease 绑定 journal。
func (w *Workflow) runDAGOwner(parent context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, opening bool, code []byte) (info syncclient.DAGRecoveryInfo, err error) {
	info.RotationRequired = true
	if r == nil {
		return info, ErrDAGOwnerMissing
	}
	e, ctx, err := r.acquire(parent, scope, opening)
	if err != nil {
		return info, err
	}
	var target *dagOwnerTarget
	attached := false
	defer func() {
		if target != nil {
			err = errors.Join(err, e.port.detach(target))
		}
		if attached {
			w.detachDAGOwner()
		}
		err = r.finish(e, ctx, err)
		if err != nil {
			info = syncclient.DAGRecoveryInfo{RotationRequired: true}
		}
	}()
	identity, err := w.attachDAGOwnerState(e.invalidate, !opening)
	if err != nil {
		return info, err
	}
	attached = true
	if !opening && identity != e.identity {
		return info, ErrDAGOwnerBinding
	}
	journal, err := w.newRecoveryDAGJournal()
	if err != nil {
		return info, err
	}
	preparation, err := w.newDAGPreparationStore()
	if err != nil {
		return info, err
	}
	target = &dagOwnerTarget{entry: e, ctx: ctx, journal: journal, preparation: preparation}
	if err = e.port.attach(target); err != nil {
		target = nil
		return info, err
	}
	if opening {
		e.identity = identity
		w.mu.Lock()
		httpClient, now := w.http, w.now
		w.mu.Unlock()
		var session *syncclient.DAGRecoverySession
		session, err = syncclient.OpenDAGRecoverySession(ctx, syncclient.DAGRecoveryConfig{Endpoint: identity.Binding.Endpoint, HTTPClient: httpClient, AccountID: identity.Binding.AccountID, AccountGeneration: identity.Binding.AccountGeneration, Now: now, Journal: &e.port, Preparation: &e.port}, string(code))
		if err != nil {
			return info, err
		}
		e.session = session
	}
	verified, err := e.session.VerifiedBinding()
	if err != nil {
		return info, err
	}
	if verified.Profile != cryptox.RecoveryDAGCapability || verified.Endpoint != identity.Binding.Endpoint || verified.AccountID != identity.Binding.AccountID || verified.AccountGeneration != identity.Binding.AccountGeneration || opening && (!verified.RotationRequired || verified.PendingID != "" || verified.PendingKind != "" || verified.PendingHash != "") {
		return info, ErrDAGOwnerBinding
	}
	if opening {
		e.binding = verified
		if err = r.pinDeadline(e, verified.ExpiresAt); err != nil {
			return info, err
		}
	} else if verified != e.binding {
		return info, ErrDAGOwnerBinding
	}
	info, err = e.session.Info()
	if err != nil {
		return info, err
	}
	if info.RotationRequired != e.binding.RotationRequired || info.TrustedDevice {
		return info, ErrDAGOwnerBinding
	}
	if err = e.port.OwnerAlive(); err != nil {
		return info, err
	}
	return info, nil
}

// OpenDAGRecoveryOwner 只开全新只读受限 owner；已有原包一律留给 S2a。
func (w *Workflow) OpenDAGRecoveryOwner(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, completeCurrentCode []byte) (syncclient.DAGRecoveryInfo, error) {
	defer clear(completeCurrentCode)
	if len(completeCurrentCode) == 0 || len(completeCurrentCode) > 512 {
		return syncclient.DAGRecoveryInfo{RotationRequired: true}, ErrDAGOwnerBinding
	}
	seed, err := cryptox.DecodeRecoveryCode(string(completeCurrentCode))
	clear(seed)
	if err != nil {
		return syncclient.DAGRecoveryInfo{RotationRequired: true}, err
	}
	return w.runDAGOwner(ctx, r, scope, true, completeCurrentCode)
}

// RecoveryDAGOwnerInfo 是当次 lease 下核验的已有会话元数据；不刷新网络、不写状态。
func (w *Workflow) RecoveryDAGOwnerInfo(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope) (syncclient.DAGRecoveryInfo, error) {
	return w.runDAGOwner(ctx, r, scope, false, nil)
}
