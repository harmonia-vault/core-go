package mobilebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/harmonia-vault/core-go/mobilebridge/internal/recoverysessions"
	"sync/atomic"
	"testing"
	"time"
)

type typedAtomicNativeFixture struct {
	atomicSealedFixture
	checks, cas int
	failCheck   int
}

func (s *typedAtomicNativeFixture) CheckSealed(expected []byte) error {
	s.checks++
	if s.checks == s.failCheck {
		return errors.New("synthetic check rejection")
	}
	return s.atomicSealedFixture.CheckSealed(expected)
}
func (s *typedAtomicNativeFixture) CompareAndSwapSealed(expected, next []byte) error {
	s.cas++
	return s.atomicSealedFixture.CompareAndSwapSealed(expected, next)
}
func TestTypedAtomicNativeOpenPreservesCheckAndCAS(t *testing.T) {
	d, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	slot := &typedAtomicNativeFixture{}
	v, err := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic-native-slot", nil, nil, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if slot.checks != 2 {
		t.Fatal("opener did not check captured state at both boundaries")
	}
	plain, err := v.workflow.ExportProtectedState()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if err = v.saveCAS(v.protectedSHA256, plain); err != nil {
		t.Fatal(err)
	}
	if slot.cas != 1 || len(slot.read()) == 0 {
		t.Fatal("typed provider lost CAS callback")
	}
	current := slot.read()
	if err = v.checkProtected(v.protectedSHA256); err != nil {
		t.Fatal(err)
	}
	slot.packet = append(bytes.Clone(current), 1)
	if err = v.checkProtected(v.protectedSHA256); err == nil {
		t.Fatal("stale owner stayed live")
	}
	if err = v.saveCAS(v.protectedSHA256, plain); err == nil || slot.cas != 1 {
		t.Fatal("failed Check permitted later CAS")
	}
}
func TestTypedAtomicNativeOpenRejectsFailedBoundary(t *testing.T) {
	for _, boundary := range []int{1, 2} {
		d, err := NewDevice()
		if err != nil {
			t.Fatal(err)
		}
		slot := &typedAtomicNativeFixture{failCheck: boundary}
		v, err := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic-native-slot", nil, nil, slot)
		if err == nil || v != nil || len(slot.read()) != 0 {
			t.Fatal("failed captured boundary opened or wrote")
		}
		d.Close()
	}
}

type atomicNativeBarrierOwner struct {
	release           chan struct{}
	closed, cancelled atomic.Int32
}

func (o *atomicNativeBarrierOwner) Cancel() { o.cancelled.Add(1) }
func (o *atomicNativeBarrierOwner) Close()  { <-o.release; o.closed.Add(1) }
func TestNativeInvalidateDoesNotDrainInsideCallback(t *testing.T) {
	pub := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	x := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	id := sha256.Sum256(bytes.Repeat([]byte{1}, 32))
	digest := sha256.Sum256([]byte("synthetic-public-binding"))
	scope := recoverysessions.Scope{Namespace: "synthetic.native", Slot: "slot-owner-test", Endpoint: "https://synthetic.example.invalid", DeviceID: hex.EncodeToString(id[:]), DeviceSigningPublicKey: pub, DeviceReceivingPublicKey: x}
	binding := recoverysessions.Binding{Scope: scope, SessionEpoch: 0, AuthorityHeadHash: hex.EncodeToString(digest[:]), RootDeviceID: scope.DeviceID, AccountID: "synthetic-account", AccountGeneration: "1", RecoveryGeneration: "2", RootSigningPublicKey: pub, RootReceivingPublicKey: x, RecoverySigningPublicKey: pub, RecoveryReceivingPublicKey: x, InitializationProposalHash: hex.EncodeToString(digest[:]), SessionHash: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Unix() + 300}
	reg, err := recoverysessions.New(scope)
	if err != nil {
		t.Fatal(err)
	}
	owner := &atomicNativeBarrierOwner{release: make(chan struct{})}
	handle, err := reg.Install(binding, owner)
	if err != nil {
		t.Fatal(err)
	}
	r := &RecoveryRegistry{registry: reg, scope: scope, handle: handle, binding: binding}
	ctx, cancel := context.WithCancel(context.Background())
	v := &VaultWorkflow{recoveryRegistry: r, cancel: cancel}
	entered, callbackRelease, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- reg.Run(ctx, handle, binding, func(ctx context.Context, lease *recoverysessions.Lease) error {
			close(entered)
			<-callbackRelease
			if _, e := lease.Owner(); e == nil {
				return errors.New("invalidated lease remained usable")
			}
			return ctx.Err()
		})
	}()
	<-entered
	invalidated := make(chan struct{})
	go func() { v.Invalidate(); r.Invalidate(); close(invalidated) }()
	select {
	case <-invalidated:
	case <-time.After(time.Second):
		t.Fatal("Invalidate waited for Close/callback")
	}
	if ctx.Err() == nil || owner.closed.Load() != 0 || owner.cancelled.Load() != 0 || !v.saveFailed.Load() {
		t.Fatal("Invalidate drained owner or did not cancel")
	}
	if err = reg.Run(context.Background(), handle, binding, func(context.Context, *recoverysessions.Lease) error { return nil }); err == nil {
		t.Fatal("old handle reopened")
	}
	drained := make(chan struct{})
	go func() { v.Close(); r.Close(); close(drained) }()
	select {
	case <-drained:
		t.Fatal("Close ignored owner barrier")
	case <-time.After(20 * time.Millisecond):
	}
	close(callbackRelease)
	close(owner.release)
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("cancelled callback succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("callback did not finish")
	}
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("final Close did not drain")
	}
	r.Clear()
	r.Close()
	v.Close()
	if owner.closed.Load() != 1 || owner.cancelled.Load() != 1 {
		t.Fatal("owner Close was not exactly once")
	}
}
