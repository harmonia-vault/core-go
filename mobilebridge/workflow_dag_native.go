package mobilebridge

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harmonia-vault/core-go/mobileworkflow"
)

// NativeDAGRegistry 仅可信 native 宿主持有。PlatformEpoch 为跨操作稳定生命周期，
// 不证明认证；本片不开放业务 dispatch、MethodChannel 或任意签名/owner 导入。
// 未保留 Workflow、Device、材料或存储 provider；普通 Workflow.Close 只 detach。
type NativeDAGRegistry struct {
	mu        sync.Mutex
	cond      *sync.Cond
	scope     mobileworkflow.DAGOwnerScope
	domain    *mobileworkflow.DAGRecoveryRegistry
	device    nativeDAGDeviceBinding
	dead      atomic.Bool
	active    map[uint64]context.CancelFunc
	next      uint64
	closeOnce sync.Once
	closed    chan struct{}
}
type nativeDAGDeviceBinding struct{ endpoint, deviceID, signing, receiving string }

var errNativeDAGBusy = errors.New("native DAG operation busy")

func (*NativeDAGRegistry) String() string               { return "native DAG registry (opaque)" }
func (*NativeDAGRegistry) GoString() string             { return "native DAG registry (opaque)" }
func (*NativeDAGRegistry) MarshalJSON() ([]byte, error) { return nil, errInput }
func (*NativeDAGRegistry) MarshalText() ([]byte, error) { return nil, errInput }
func (*NativeDAGRegistry) UnmarshalJSON([]byte) error   { return errInput }
func (*NativeDAGRegistry) UnmarshalText([]byte) error   { return errInput }

func NewNativeDAGRegistry(namespace, slot string, platformEpoch int64) (*NativeDAGRegistry, error) {
	if platformEpoch <= 0 {
		return nil, errInput
	}
	scope := mobileworkflow.DAGOwnerScope{Namespace: namespace, Slot: slot, PlatformEpoch: uint64(platformEpoch)}
	domain, err := mobileworkflow.NewDAGRecoveryRegistry(scope)
	if err != nil {
		return nil, errInput
	}
	r := &NativeDAGRegistry{scope: scope, domain: domain, active: make(map[uint64]context.CancelFunc), closed: make(chan struct{})}
	r.cond = sync.NewCond(&r.mu)
	return r, nil
}

// Invalidate 只发布永久死票并取消自己记录的 context；绝不在 callback/gate 内
// 调用 domain.Clear/Close。native 必须锁外调用，worker 排空后调用 Close。
func (r *NativeDAGRegistry) Invalidate() {
	if r == nil {
		return
	}
	r.dead.Store(true)
	r.mu.Lock()
	for _, cancel := range r.active {
		cancel()
	}
	r.mu.Unlock()
}
func (r *NativeDAGRegistry) Close() {
	if r == nil {
		return
	}
	r.Invalidate()
	r.closeOnce.Do(func() {
		r.mu.Lock()
		for len(r.active) > 0 {
			r.cond.Wait()
		}
		domain := r.domain
		r.domain = nil
		r.mu.Unlock()
		if domain != nil {
			domain.Close()
		}
		close(r.closed)
	})
	<-r.closed
}

func (v *VaultWorkflow) AttachDAGRegistry(r *NativeDAGRegistry) error {
	if v == nil || r == nil {
		return errInput
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.workflow == nil || len(v.key) != 32 || v.saveFailed.Load() {
		return errClosed
	}
	if _, ok := v.store.(AtomicSealedStateStore); !ok {
		return mobileworkflow.ErrDAGAtomicStoreRequired
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dead.Load() || r.domain == nil {
		return errClosed
	}
	if len(r.active) != 0 {
		return errNativeDAGBusy
	}
	if v.binding.Namespace != r.scope.Namespace+"\x00harmonia/workflow-state/v1\x00"+r.scope.Slot {
		return errInput
	}
	next := nativeDAGDeviceBinding{v.binding.Endpoint, v.binding.DeviceID, v.binding.SigningPublicKey, v.binding.ReceivingPublicKey}
	if r.device != (nativeDAGDeviceBinding{}) && r.device != next {
		r.dead.Store(true)
		return errInput
	}
	v.cancelMu.Lock()
	defer v.cancelMu.Unlock()
	if v.dagRegistry != nil && v.dagRegistry != r {
		return errInput
	}
	r.device = next
	v.dagRegistry = r
	return nil
}
func (v *VaultWorkflow) invalidateNativeDAGRegistry() {
	v.cancelMu.Lock()
	r := v.dagRegistry
	v.cancelMu.Unlock()
	if r != nil {
		r.Invalidate()
	}
}
func (v *VaultWorkflow) detachNativeDAGRegistry() {
	v.cancelMu.Lock()
	r := v.dagRegistry
	v.dagRegistry = nil
	v.cancelMu.Unlock()
	if r != nil && v.saveFailed.Load() {
		r.Close()
	}
}

// reserve/finish 只供本包后续封闭 typed DAG dispatch；没有公开任意 callback API。
// 操作 context 全由 wrapper 记录；先 finish 排空，再允许 worker Close。
func (r *NativeDAGRegistry) reserve(parent context.Context) (uint64, context.Context, error) {
	if parent == nil || parent.Err() != nil || r.dead.Load() {
		return 0, nil, errClosed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dead.Load() || r.domain == nil {
		return 0, nil, errClosed
	}
	if len(r.active) != 0 {
		return 0, nil, errNativeDAGBusy
	}
	if r.next == ^uint64(0) {
		r.dead.Store(true)
		return 0, nil, errClosed
	}
	r.next++
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	r.active[r.next] = cancel
	return r.next, ctx, nil
}
func (r *NativeDAGRegistry) finish(id uint64) {
	r.mu.Lock()
	if cancel, ok := r.active[id]; ok {
		cancel()
		delete(r.active, id)
	}
	r.cond.Broadcast()
	r.mu.Unlock()
}
