package mobilebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeDAGRegistryScopeAndNoSerialization(t *testing.T) {
	for _, args := range []struct {
		namespace, slot string
		epoch           int64
	}{
		{"", "synthetic", 1}, {"synthetic.native", "../slot", 1}, {"synthetic.native", "slot", 0}, {"synthetic.native", "slot", -1},
	} {
		if r, e := NewNativeDAGRegistry(args.namespace, args.slot, args.epoch); e == nil || r != nil {
			t.Fatal("invalid native scope accepted")
		}
	}
	r, e := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if _, e = json.Marshal(r); e == nil {
		t.Fatal("opaque registry serialized")
	}
	if _, e = r.MarshalText(); e == nil {
		t.Fatal("opaque registry serialized")
	}
	if r.UnmarshalJSON([]byte("{}")) == nil || r.UnmarshalText([]byte("synthetic")) == nil {
		t.Fatal("opaque registry imported")
	}
	if fmt.Sprintf("%v", r) != "native DAG registry (opaque)" || fmt.Sprintf("%#v", r) != "native DAG registry (opaque)" {
		t.Fatal("opaque registry formatting exposed state")
	}
}
func TestNativeDAGNormalWorkflowCloseOnlyDetaches(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	r, e := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	scope := "synthetic.native\x00harmonia/workflow-state/v1\x00slot"
	for operation := 0; operation < 2; operation++ {
		store := &typedAtomicNativeFixture{}
		v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", scope, nil, nil, store)
		if e != nil {
			t.Fatal(e)
		}
		if e = v.AttachDAGRegistry(r); e != nil {
			t.Fatal(e)
		}
		if r.scope.PlatformEpoch != 41 || r.dead.Load() {
			t.Fatal("normal auth changed lifecycle")
		}
		v.Close()
		if v.dagRegistry != nil || r.dead.Load() || r.domain == nil {
			t.Fatal("normal Close disposed cross-operation registry")
		}
	}
}
func TestNativeDAGAttachmentRejectsScopeDeviceOrSaveOnly(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	r, e := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	scope := "synthetic.native\x00harmonia/workflow-state/v1\x00slot"
	v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", scope, nil, nil, &typedAtomicNativeFixture{})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	if e = v.AttachDAGRegistry(r); e != nil {
		t.Fatal(e)
	}
	other, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	changed, e := other.OpenAtomicWorkflow("https://synthetic.example.invalid", scope, nil, nil, &typedAtomicNativeFixture{})
	if e != nil {
		t.Fatal(e)
	}
	defer changed.Close()
	if changed.AttachDAGRegistry(r) == nil || !r.dead.Load() {
		t.Fatal("device replacement retained registry")
	}
	fresh, _ := NewNativeDAGRegistry("synthetic.native", "slot", 42)
	defer fresh.Close()
	wrong, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "wrong-slot", nil, nil, &typedAtomicNativeFixture{})
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	if wrong.AttachDAGRegistry(fresh) == nil {
		t.Fatal("wrong namespace accepted")
	}
	plain, e := d.OpenWorkflow("https://synthetic.example.invalid", scope, nil, nil, &memorySealed{})
	if e != nil {
		t.Fatal(e)
	}
	defer plain.Close()
	if plain.AttachDAGRegistry(fresh) == nil {
		t.Fatal("save-only proxy accepted")
	}
}
func TestNativeDAGInvalidateCancelsAndDoesNotDrain(t *testing.T) {
	r, e := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	if e != nil {
		t.Fatal(e)
	}
	id, ctx, e := r.reserve(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = r.reserve(context.Background()); !errors.Is(e, errNativeDAGBusy) {
		t.Fatal("concurrent operation accepted")
	}
	v := &VaultWorkflow{dagRegistry: r}
	done := make(chan struct{})
	go func() { v.Invalidate(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Invalidate blocked on drain")
	}
	if ctx.Err() == nil || !v.saveFailed.Load() {
		t.Fatal("active context not cancelled")
	}
	if _, _, e = r.reserve(context.Background()); e == nil {
		t.Fatal("new lease survived invalidate")
	}
	drained := make(chan struct{})
	go func() { r.Close(); close(drained) }()
	select {
	case <-drained:
		t.Fatal("Close did not wait active callback")
	case <-time.After(20 * time.Millisecond):
	}
	r.finish(id)
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("Close failed after callback drain")
	}
	r.Close()
	if r.domain != nil {
		t.Fatal("domain registry retained")
	}
}
func TestNativeDAGSealFailureInvalidatesBeforeClose(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	r, e := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	s := &typedAtomicNativeFixture{}
	v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic.native\x00harmonia/workflow-state/v1\x00slot", nil, nil, s)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	if e = v.AttachDAGRegistry(r); e != nil {
		t.Fatal(e)
	}
	id, ctx, e := r.reserve(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	s.packet = bytes.Repeat([]byte{1}, 2)
	if e = v.checkProtected(v.protectedSHA256); e == nil {
		t.Fatal("changed capture accepted")
	}
	if !r.dead.Load() || ctx.Err() == nil {
		t.Fatal("persistence failure retained registry/context")
	}
	r.finish(id)
	v.Close()
	if r.domain != nil {
		t.Fatal("failed operation did not close after drain")
	}
}
func TestNativeDAGInvalidateAllRecordedContexts(t *testing.T) {
	// reserve只允许一个；故障/未来记录遗漏回归仍验证Invalidate遍历全部私有记录。
	r, e := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	if e != nil {
		t.Fatal(e)
	}
	c1, cancel1 := context.WithCancel(context.Background())
	c2, cancel2 := context.WithCancel(context.Background())
	var calls atomic.Int32
	r.mu.Lock()
	r.active[1] = func() { calls.Add(1); cancel1() }
	r.active[2] = func() { calls.Add(1); cancel2() }
	r.mu.Unlock()
	r.Invalidate()
	if c1.Err() == nil || c2.Err() == nil || calls.Load() != 2 {
		t.Fatal("some context survived invalidate")
	}
	r.finish(1)
	r.finish(2)
	r.Close()
}
