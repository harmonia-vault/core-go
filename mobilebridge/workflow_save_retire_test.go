package mobilebridge

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/mobilebridge/internal/recoverysessions"
)

type lockingSaveOwner struct {
	session          sync.Mutex
	flow             *VaultWorkflow
	canceled, closed atomic.Int32
}

func (o *lockingSaveOwner) Cancel() { o.canceled.Add(1) }
func (o *lockingSaveOwner) Close() {
	o.session.Lock()
	defer o.session.Unlock()
	// If either the save callback or the outer business lock calls Close early,
	// this component fixture deadlocks instead of pretending authentication worked.
	o.flow.mu.Lock()
	defer o.flow.mu.Unlock()
	o.closed.Add(1)
}
func TestWorkflowSaveFailureInvalidatesImmediatelyAndRetiresOutsideLocks(t *testing.T) {
	d, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	store := &memorySealed{}
	v, err := d.OpenWorkflow("https://synthetic.example.invalid", "synthetic-state", nil, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	plain, err := v.workflow.ExportProtectedState()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if err = v.save(plain); err != nil {
		t.Fatal(err)
	}
	scope := recoverysessions.Scope{Namespace: "synthetic-native", Slot: "synthetic-slot", Endpoint: v.binding.Endpoint, DeviceID: v.binding.DeviceID, DeviceSigningPublicKey: v.binding.SigningPublicKey, DeviceReceivingPublicKey: v.binding.ReceivingPublicKey}
	binding := recoverysessions.Binding{Scope: scope, SessionEpoch: 0, AccountID: "synthetic-account", AccountGeneration: "1", RecoveryGeneration: "1", RootDeviceID: scope.DeviceID, RootSigningPublicKey: scope.DeviceSigningPublicKey, RootReceivingPublicKey: scope.DeviceReceivingPublicKey, RecoverySigningPublicKey: scope.DeviceSigningPublicKey, RecoveryReceivingPublicKey: scope.DeviceReceivingPublicKey, AuthorityHeadHash: strings.Repeat("a", 64), InitializationProposalHash: strings.Repeat("b", 64), SessionHash: strings.Repeat("c", 64), ExpiresAt: time.Now().Unix() + 60}
	reg, err := recoverysessions.New(scope)
	if err != nil {
		t.Fatal(err)
	}
	owner := &lockingSaveOwner{flow: v}
	handle, err := reg.Install(binding, owner)
	if err != nil {
		t.Fatal(err)
	}
	registry := &RecoveryRegistry{registry: reg, scope: scope, handle: handle, binding: binding}
	v.recoveryRegistry = registry
	entered, unwind := make(chan context.Context, 1), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- reg.Run(context.Background(), handle, binding, func(ctx context.Context, _ *recoverysessions.Lease) error { entered <- ctx; <-unwind; return nil })
	}()
	active := <-entered
	owner.session.Lock()
	v.mu.Lock()
	store.fail = true
	failed := make(chan error, 1)
	go func() { failed <- v.save(plain) }()
	select {
	case err = <-failed:
		if err == nil {
			t.Fatal("failed save reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("save callback reentered owner close while locks held")
	}
	if active.Err() == nil || !v.saveFailed.Load() {
		t.Fatal("save failure did not immediately cancel/gate owner")
	}
	if owner.closed.Load() != 0 || owner.canceled.Load() != 0 {
		t.Fatal("save callback called owner before unlocking")
	}
	if err = reg.Run(context.Background(), handle, binding, func(context.Context, *recoverysessions.Lease) error {
		t.Fatal("new lease executed after failed save")
		return nil
	}); !errors.Is(err, recoverysessions.ErrMissing) {
		t.Fatal("failed owner accepted a new lease", err)
	}
	v.mu.Unlock()
	owner.session.Unlock()
	close(unwind)
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("in-flight operation lost cancellation", err)
	}
	retired := make(chan error, 1)
	go func() {
		_, e := v.Execute(`{"version":1,"operation":"view","endpoint":"https://synthetic.example.invalid"}`)
		retired <- e
	}()
	select {
	case err = <-retired:
		if !errors.Is(err, errClosed) {
			t.Fatal("failed workflow still executed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("outer operation retired owner while holding business lock")
	}
	if owner.closed.Load() != 1 || owner.canceled.Load() != 1 {
		t.Fatal("owner was not retired exactly once")
	}
	store.fail = false
	if v.save(plain) == nil {
		t.Fatal("failed workflow saved again without authenticated reopen")
	}
	v.Close()
	if owner.closed.Load() != 1 {
		t.Fatal("Close repeated owner destruction")
	}
}
