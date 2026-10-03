// Package recoverysessions 管理仅原生进程内的恢复签名资源生命周期。
// 它不认证、不签名、不联网，也没有存储或对外绑定入口；调用方必须先完成
// 本次CryptoObject强认证、解包和Go受保护上下文核验，再传入精确Binding。
package recoverysessions

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

var (
	ErrBinding    = errors.New("native recovery binding rejected")
	ErrMissing    = errors.New("native recovery session missing; restart with complete old code")
	ErrBusy       = errors.New("native recovery operation already active")
	ErrClosed     = errors.New("native recovery registry closed")
	ErrNativeOnly = errors.New("native recovery handle cannot be serialized")
)

const maxTTL = 5 * time.Minute

// Scope只由固定原生配置和本次认证后的设备身份构造，不接受Dart字段。
type Scope struct {
	Namespace, Slot, Endpoint, DeviceID              string
	DeviceSigningPublicKey, DeviceReceivingPublicKey string
}

// Binding必须来自Go已核验的恢复对象和认证后状态，不能用文件header或server数组替代。
// 全部字段都是公开身份/摘要；没有bearer、seed、code、Ed/X私钥或AES钥。
type Binding struct {
	Scope
	AccountID, AccountGeneration, RecoveryGeneration     string
	RootSigningPublicKey, RootReceivingPublicKey         string
	RecoverySigningPublicKey, RecoveryReceivingPublicKey string
	InitializationProposalHash, SessionHash              string
	ExpiresAt                                            int64
	TransitionID, TransitionHash                         string
}

// EdOwner是未来typed Go RecoverySession的原生adapter；不提供RawKey或任意Sign。
// Cancel/Close必须幂等，可并发；Close须让后续typed签名失败并清可控私钥缓冲。
type EdOwner interface {
	Cancel()
	Close()
}

// Handle不能Marshal、传Dart或作为授权；只索引同一registry的进程内对象。
type Handle struct{ id, registry [32]byte }

func (Handle) String() string               { return "native recovery handle (opaque)" }
func (Handle) GoString() string             { return "native recovery handle (opaque)" }
func (Handle) MarshalJSON() ([]byte, error) { return nil, ErrNativeOnly }
func (Handle) MarshalText() ([]byte, error) { return nil, ErrNativeOnly }
func (*Handle) UnmarshalJSON([]byte) error  { return ErrNativeOnly }
func (*Handle) UnmarshalText([]byte) error  { return ErrNativeOnly }

type timer interface{ Stop() bool }
type entry struct {
	handle        Handle
	binding       Binding
	owner         EdOwner
	deadline      time.Time
	timer         timer
	busy, retired bool
	cancel        context.CancelFunc
	closeOnce     sync.Once
	closed        chan struct{}
}

func (e *entry) closeOwner() {
	e.closeOnce.Do(func() { e.owner.Cancel(); e.owner.Close(); close(e.closed) })
}

type Registry struct {
	mu       sync.Mutex
	scope    Scope
	identity [32]byte
	current  *entry
	disposed bool
	now      func() time.Time
	after    func(time.Duration, func()) timer
}

func New(scope Scope) (*Registry, error) {
	return newRegistry(scope, time.Now, func(d time.Duration, f func()) timer { return time.AfterFunc(d, f) })
}
func newRegistry(scope Scope, now func() time.Time, after func(time.Duration, func()) timer) (*Registry, error) {
	if !validScope(scope) || now == nil || after == nil {
		return nil, ErrBinding
	}
	r := &Registry{scope: scope, now: now, after: after}
	if _, err := rand.Read(r.identity[:]); err != nil {
		return nil, ErrClosed
	}
	return r, nil
}

// Install移交owner，包含失败分支。每个registry只允许一个会话，忙时不能替换。
func (r *Registry) Install(binding Binding, owner EdOwner) (Handle, error) {
	if owner == nil {
		return Handle{}, ErrBinding
	}
	transferred := false
	defer func() {
		if !transferred {
			owner.Cancel()
			owner.Close()
		}
	}()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.disposed {
		return Handle{}, ErrClosed
	}
	now := r.now()
	if now.Unix() <= 0 {
		return Handle{}, ErrBinding
	}
	if binding.Scope != r.scope || !validBinding(binding) || binding.ExpiresAt <= now.Unix() || binding.ExpiresAt > now.Unix()+305 {
		return Handle{}, ErrBinding
	}
	if e := r.current; e != nil {
		if e.busy {
			return Handle{}, ErrBusy
		}
		select {
		case <-e.closed:
			r.current = nil
		default:
			return Handle{}, ErrBusy
		}
	}
	handle := Handle{registry: r.identity}
	if _, err := rand.Read(handle.id[:]); err != nil {
		return Handle{}, ErrClosed
	}
	deadline := now.Add(min(maxTTL, time.Unix(binding.ExpiresAt, 0).Sub(now)))
	if binding.TransitionID != "" && binding.ExpiresAt > now.Unix()+125 {
		return Handle{}, ErrBinding
	}
	if !deadline.After(now) {
		return Handle{}, ErrBinding
	}
	e := &entry{handle: handle, binding: binding, owner: owner, deadline: deadline, closed: make(chan struct{})}
	r.current = e
	e.timer = r.after(deadline.Sub(now), func() { r.expire(handle) })
	transferred = true
	return handle, nil
}

// Run只做生命周期/metadata核对，不能代替Android认证。
// caller须先本次CryptoObject成功+AES解包，再从typedGo取expected，并只在本次操作内调用。
func (r *Registry) Run(ctx context.Context, handle Handle, expected Binding, operation func(context.Context, *Lease) error) error {
	if ctx == nil || operation == nil {
		return ErrBinding
	}
	r.mu.Lock()
	e := r.current
	if r.disposed {
		r.mu.Unlock()
		return ErrClosed
	}
	if e == nil || e.handle != handle || e.retired {
		r.mu.Unlock()
		return ErrMissing
	}
	if !r.now().Before(e.deadline) {
		r.mu.Unlock()
		r.retire(handle, false)
		return ErrMissing
	}
	if expected != e.binding {
		r.mu.Unlock()
		return ErrBinding
	}
	if e.busy {
		r.mu.Unlock()
		return ErrBusy
	}
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return err
	}
	operationCtx, cancel := context.WithCancel(ctx)
	e.busy = true
	e.cancel = cancel
	lease := &Lease{registry: r, entry: e, context: operationCtx, live: true}
	r.mu.Unlock()
	defer func() {
		cancel()
		r.mu.Lock()
		lease.live = false
		e.busy = false
		e.cancel = nil
		r.mu.Unlock()
	}()
	err := operation(operationCtx, lease)
	if operationCtx.Err() != nil {
		return operationCtx.Err()
	}
	r.mu.Lock()
	invalid := e.retired || r.disposed || !r.now().Before(e.deadline)
	r.mu.Unlock()
	if invalid {
		r.retire(handle, false)
		return ErrMissing
	}
	return err
}

// Lease仅本次Run回调内有效，不能缓存跨操作复用。
type Lease struct {
	registry *Registry
	entry    *entry
	context  context.Context
	live     bool
}

func (l *Lease) Owner() (EdOwner, error) {
	r := l.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if !l.live || l.entry.retired || r.disposed || l.context.Err() != nil || !r.now().Before(l.entry.deadline) {
		return nil, ErrMissing
	}
	return l.entry.owner, nil
}

// Advance只接受同一恢复身份下的原transition；不能换id/hash、换session或延长期限。
// future typedGo callback只有同步密封成功后才能提交此authoritative投影。
func (l *Lease) Advance(next Binding) error {
	r := l.registry
	r.mu.Lock()
	e := l.entry
	if !l.live || e.retired || r.disposed || l.context.Err() != nil || !r.now().Before(e.deadline) {
		r.mu.Unlock()
		return ErrMissing
	}
	if !validBinding(next) || immutable(next) != immutable(e.binding) || next.TransitionID == "" {
		r.mu.Unlock()
		return ErrBinding
	}
	if next.ExpiresAt > e.binding.ExpiresAt || e.binding.TransitionID != "" && (next.TransitionID != e.binding.TransitionID || next.TransitionHash != e.binding.TransitionHash) {
		r.mu.Unlock()
		return ErrBinding
	}
	now := r.now()
	if next.ExpiresAt <= now.Unix() || next.ExpiresAt > now.Unix()+125 {
		r.mu.Unlock()
		return ErrBinding
	}
	deadline := minTime(e.deadline, now.Add(time.Unix(next.ExpiresAt, 0).Sub(now)))
	if !deadline.After(now) {
		r.mu.Unlock()
		r.retire(e.handle, false)
		return ErrMissing
	}
	e.binding = next
	e.deadline = deadline
	e.timer.Stop()
	e.timer = r.after(deadline.Sub(now), func() { r.expire(e.handle) })
	r.mu.Unlock()
	return nil
}
func immutable(b Binding) Binding {
	b.TransitionID = ""
	b.TransitionHash = ""
	b.ExpiresAt = 0
	return b
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (r *Registry) expire(handle Handle) {
	r.mu.Lock()
	e := r.current
	expired := e != nil && e.handle == handle && !r.now().Before(e.deadline)
	r.mu.Unlock()
	if expired {
		r.retire(handle, false)
	}
}

// Clear用于Logout/Invalidate；Close用于dispose。active context立即取消，owner单次清理。
func (r *Registry) Clear() { r.retire(Handle{}, false) }
func (r *Registry) Close() { r.retire(Handle{}, true) }
func (r *Registry) retire(handle Handle, dispose bool) {
	r.mu.Lock()
	if dispose {
		r.disposed = true
	}
	e := r.current
	if e == nil || handle != (Handle{}) && e.handle != handle {
		r.mu.Unlock()
		return
	}
	e.retired = true
	if e.timer != nil {
		e.timer.Stop()
	}
	if e.cancel != nil {
		e.cancel()
	}
	r.mu.Unlock()
	e.closeOwner()
}
