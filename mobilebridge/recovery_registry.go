package mobilebridge

import (
	"context"
	"errors"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/mobilebridge/internal/recoverysessions"
	"github.com/harmonia-vault/core-go/mobileworkflow"
)

// RecoveryRegistry只有可信原生插件持有。Handle/owner不导出JNI、JSON、Dart或磁盘。
// 没有认证bool/rawSign/rawKey；每op新CryptoObject及保护文件认证由Kotlin完成。
type RecoveryRegistry struct {
	mu              sync.Mutex
	namespace, slot string
	registry        *recoverysessions.Registry
	scope           recoverysessions.Scope
	handle          recoverysessions.Handle
	binding         recoverysessions.Binding
	closed          bool
}

func (*RecoveryRegistry) String() string               { return "native process recovery registry (opaque)" }
func (*RecoveryRegistry) MarshalJSON() ([]byte, error) { return nil, recoverysessions.ErrNativeOnly }
func (*RecoveryRegistry) MarshalText() ([]byte, error) { return nil, recoverysessions.ErrNativeOnly }

func NewRecoveryRegistry(namespace, slot string) (*RecoveryRegistry, error) {
	if namespace == "" || len(namespace) > 256 || !utf8.ValidString(namespace) || strings.ContainsAny(namespace, "\x00\r\n\t/\\") || slot == "" || len(slot) > 128 || !utf8.ValidString(slot) || strings.ContainsAny(slot, "\x00\r\n\t/\\") {
		return nil, errInput
	}
	return &RecoveryRegistry{namespace: namespace, slot: slot}, nil
}
func (r *RecoveryRegistry) Clear() {
	if r == nil {
		return
	}
	r.mu.Lock()
	reg := r.registry
	r.handle = recoverysessions.Handle{}
	r.binding = recoverysessions.Binding{}
	r.mu.Unlock()
	if reg != nil {
		reg.Clear()
	}
}
func (r *RecoveryRegistry) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	reg := r.registry
	r.handle = recoverysessions.Handle{}
	r.binding = recoverysessions.Binding{}
	r.mu.Unlock()
	if reg != nil {
		reg.Close()
	}
}

// 仅可信native成功显式生成新device后调用；disposed不能复活。旧scope/owner彻底关闭。
func (r *RecoveryRegistry) ResetForNewDevice() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return recoverysessions.ErrClosed
	}
	old := r.registry
	r.registry = nil
	r.scope = recoverysessions.Scope{}
	r.handle = recoverysessions.Handle{}
	r.binding = recoverysessions.Binding{}
	r.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}
func (v *VaultWorkflow) AttachRecoveryRegistry(r *RecoveryRegistry) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if r == nil || v.workflow == nil {
		return errClosed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || v.binding.Namespace != r.namespace+"\x00harmonia/workflow-state/v1\x00"+r.slot {
		return errInput
	}
	scope := recoverysessions.Scope{Namespace: r.namespace, Slot: r.slot, Endpoint: v.binding.Endpoint, DeviceID: v.binding.DeviceID, DeviceSigningPublicKey: v.binding.SigningPublicKey, DeviceReceivingPublicKey: v.binding.ReceivingPublicKey}
	if r.registry == nil {
		reg, e := recoverysessions.New(scope)
		if e != nil {
			return e
		}
		r.registry = reg
		r.scope = scope
	} else if r.scope != scope {
		r.registry.Close()
		r.closed = true
		return recoverysessions.ErrBinding
	}
	v.cancelMu.Lock()
	v.recoveryRegistry = r
	v.cancelMu.Unlock()
	return nil
}
func registryBinding(b mobileworkflow.RecoverySessionBinding, scope recoverysessions.Scope) recoverysessions.Binding {
	return recoverysessions.Binding{Scope: scope, SessionEpoch: b.SessionEpoch, AuthorityHeadHash: b.AuthorityHeadHash, RootDeviceID: b.RootDeviceID, AccountID: b.AccountID, AccountGeneration: b.AccountGeneration, RecoveryGeneration: b.RecoveryGeneration, RootSigningPublicKey: b.RootSigningPublicKey, RootReceivingPublicKey: b.RootReceivingPublicKey, RecoverySigningPublicKey: b.RecoverySigningPublicKey, RecoveryReceivingPublicKey: b.RecoveryReceivingPublicKey, InitializationProposalHash: b.InitializationProposalHash, SessionHash: b.SessionHash, ExpiresAt: b.ExpiresAt, TransitionID: b.TransitionID, TransitionHash: b.TransitionHash}
}
func (v *VaultWorkflow) installRecoveryOwner(owner *mobileworkflow.RecoverySession) error {
	r := v.recoveryRegistry
	if r == nil || owner == nil {
		if owner != nil {
			owner.Close()
		}
		return mobileworkflow.ErrRecoverySession
	}
	b, e := owner.Binding()
	if e != nil {
		owner.Close()
		return e
	}
	r.Clear()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.registry == nil || b.Endpoint != v.binding.Endpoint || b.DeviceID != v.binding.DeviceID || b.DeviceSigningPublicKey != v.binding.SigningPublicKey || b.DeviceReceivingPublicKey != v.binding.ReceivingPublicKey || b.AccountID != v.binding.AccountID || b.AccountGeneration != v.binding.AccountGeneration {
		owner.Close()
		return recoverysessions.ErrBinding
	}
	projected := registryBinding(b, r.scope)
	handle, e := r.registry.Install(projected, owner)
	if e != nil {
		return e
	}
	r.handle = handle
	r.binding = projected
	return nil
}
func (v *VaultWorkflow) withRecoveryOwner(ctx context.Context, operation func(context.Context) error) error {
	r := v.recoveryRegistry
	if r == nil {
		return mobileworkflow.ErrRecoverySession
	}
	r.mu.Lock()
	reg, handle, expected, closed, scope := r.registry, r.handle, r.binding, r.closed, r.scope
	r.mu.Unlock()
	if closed || reg == nil || handle == (recoverysessions.Handle{}) {
		return mobileworkflow.ErrRecoverySession
	}
	err := reg.Run(ctx, handle, expected, func(leaseCtx context.Context, lease *recoverysessions.Lease) error {
		raw, e := lease.Owner()
		if e != nil {
			return e
		}
		owner, ok := raw.(*mobileworkflow.RecoverySession)
		if !ok {
			return recoverysessions.ErrBinding
		}
		b, e := owner.Binding()
		if e != nil {
			return e
		}
		if registryBinding(b, scope) != expected {
			return recoverysessions.ErrBinding
		}
		// 关键校验来自本次Go已认证保护record，而不是registry或Dart的metadata。
		if e = v.workflow.AttachRecoverySession(owner); e != nil {
			return e
		}
		if e = operation(leaseCtx); e != nil {
			return e
		}
		b, e = owner.Binding()
		if errors.Is(e, mobileworkflow.ErrRecoverySession) {
			return nil
		} // typed签包已密封而关闭oldOwner。
		if e != nil {
			return e
		}
		next := registryBinding(b, scope)
		if next != expected {
			if e = lease.Advance(next); e != nil {
				return e
			}
			r.mu.Lock()
			if r.handle == handle {
				r.binding = next
			}
			r.mu.Unlock()
		}
		return nil
	})
	if errors.Is(err, recoverysessions.ErrMissing) || errors.Is(err, recoverysessions.ErrClosed) {
		return mobileworkflow.ErrRecoverySession
	}
	return err
}
func (v *VaultWorkflow) clearRecoveryOwner() {
	v.cancelMu.Lock()
	r := v.recoveryRegistry
	v.cancelMu.Unlock()
	if r != nil {
		r.Clear()
	}
}
