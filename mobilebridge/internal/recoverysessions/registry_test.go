package recoverysessions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type fixtureOwner struct {
	mu                sync.Mutex
	key               []byte
	cancelled, closed int
}

func (o *fixtureOwner) Cancel() { o.mu.Lock(); defer o.mu.Unlock(); o.cancelled++ }
func (o *fixtureOwner) Close()  { o.mu.Lock(); defer o.mu.Unlock(); clear(o.key); o.closed++ }
func (o *fixtureOwner) check(t *testing.T, closed int) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed != closed || o.cancelled != closed {
		t.Fatal("owner lifecycle mismatch")
	}
	if closed > 0 && !bytes.Equal(o.key, make([]byte, len(o.key))) {
		t.Fatal("owner buffer retained")
	}
}

type fixtureClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fixtureTimer
}
type fixtureTimer struct {
	clock   *fixtureClock
	at      time.Time
	fn      func()
	stopped bool
}

func (c *fixtureClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fixtureClock) After(d time.Duration, fn func()) timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := &fixtureTimer{clock: c, at: c.now.Add(d), fn: fn}
	c.timers = append(c.timers, v)
	return v
}
func (t *fixtureTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}
func (c *fixtureClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var callbacks []func()
	for _, v := range c.timers {
		if !v.stopped && !c.now.Before(v.at) {
			v.stopped = true
			callbacks = append(callbacks, v.fn)
		}
	}
	c.mu.Unlock()
	for _, f := range callbacks {
		f()
	}
}
func fixture(t *testing.T) (*Registry, *fixtureClock, Binding, *fixtureOwner) {
	t.Helper()
	clock := &fixtureClock{now: time.Now()}
	pub := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	x := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	id := sha256.Sum256(bytes.Repeat([]byte{1}, 32))
	h := sha256.Sum256([]byte("synthetic-public-digest"))
	scope := Scope{Namespace: "synthetic.native/recovery/v1", Slot: "recovery-state-v1", Endpoint: "https://synthetic.example.invalid", DeviceID: hex.EncodeToString(id[:]), DeviceSigningPublicKey: pub, DeviceReceivingPublicKey: x}
	b := Binding{Scope: scope, SessionEpoch: 1, AuthorityHeadHash: hex.EncodeToString(h[:]), RootDeviceID: scope.DeviceID, AccountID: "synthetic-account", AccountGeneration: "1", RecoveryGeneration: "2", RootSigningPublicKey: pub, RootReceivingPublicKey: x, RecoverySigningPublicKey: pub, RecoveryReceivingPublicKey: x, InitializationProposalHash: hex.EncodeToString(h[:]), SessionHash: hex.EncodeToString(h[:]), ExpiresAt: clock.Now().Unix() + 300}
	r, e := newRegistry(scope, clock.Now, clock.After)
	if e != nil {
		t.Fatal("registry setup failed")
	}
	t.Cleanup(r.Close)
	return r, clock, b, &fixtureOwner{key: bytes.Repeat([]byte{3}, 64)}
}
func TestPrivateHandleAndClosedLeaseCannotBeSerializedOrReused(t *testing.T) {
	r, _, b, o := fixture(t)
	h, e := r.Install(b, o)
	if e != nil {
		t.Fatal("install failed")
	}
	if _, e = json.Marshal(h); e == nil || h.String() != "native recovery handle (opaque)" {
		t.Fatal("native handle escaped")
	}
	var retained *Lease
	if e = r.Run(context.Background(), h, b, func(ctx context.Context, l *Lease) error {
		retained = l
		owner, e := l.Owner()
		if e != nil || owner != o {
			t.Fatal("lease owner mismatch")
		}
		return nil
	}); e != nil {
		t.Fatal("operation failed")
	}
	if _, e = retained.Owner(); !errors.Is(e, ErrMissing) {
		t.Fatal("closed lease reused")
	}
	o.check(t, 0)
	r.Clear()
	r.Close()
	o.check(t, 1)
}
func TestAuthoritativeBindingSubstitutionRejectedBeforeOwnerUse(t *testing.T) {
	r, _, b, o := fixture(t)
	h, e := r.Install(b, o)
	if e != nil {
		t.Fatal("install failed")
	}
	cases := []func(*Binding){
		func(v *Binding) { v.SessionEpoch++ }, func(v *Binding) { v.AuthorityHeadHash = string(bytes.Repeat([]byte{'c'}, 64)) }, func(v *Binding) { v.RootDeviceID = string(bytes.Repeat([]byte{'d'}, 64)) },
		func(v *Binding) { v.Endpoint = "https://other.example.invalid" }, func(v *Binding) { v.Slot = "other" }, func(v *Binding) { v.AccountID = "other" }, func(v *Binding) { v.AccountGeneration = "2" }, func(v *Binding) { v.RecoveryGeneration = "3" }, func(v *Binding) { v.RootSigningPublicKey = v.RootReceivingPublicKey }, func(v *Binding) { v.InitializationProposalHash = string(bytes.Repeat([]byte{'a'}, 64)) }, func(v *Binding) { v.SessionHash = string(bytes.Repeat([]byte{'b'}, 64)) }, func(v *Binding) { v.ExpiresAt++ }, func(v *Binding) { v.TransitionID = "different" },
	}
	for _, mutate := range cases {
		next := b
		mutate(&next)
		if e = r.Run(context.Background(), h, next, func(context.Context, *Lease) error { t.Fatal("substitution reached owner"); return nil }); !errors.Is(e, ErrBinding) {
			t.Fatal("binding substitution accepted")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if e = r.Run(cancelled, h, b, func(context.Context, *Lease) error { t.Fatal("cancelled operation reached owner"); return nil }); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled operation accepted")
	}
	other, _, _, otherOwner := fixture(t)
	otherHandle, e := other.Install(b, otherOwner)
	if e != nil {
		t.Fatal("other install failed")
	}
	if e = r.Run(context.Background(), otherHandle, b, func(context.Context, *Lease) error { t.Fatal("foreign handle accepted"); return nil }); !errors.Is(e, ErrMissing) {
		t.Fatal("foreign registry accepted")
	}
	o.check(t, 0)
}
func TestTTLClosesIdleOwnerWithoutIncomingOperation(t *testing.T) {
	for _, duration := range []time.Duration{maxTTL, 70 * time.Second} {
		t.Run(duration.String(), func(t *testing.T) {
			r, clock, b, o := fixture(t)
			if duration < maxTTL {
				b.ExpiresAt = clock.Now().Unix() + int64(duration/time.Second)
			}
			h, e := r.Install(b, o)
			if e != nil {
				t.Fatal("install failed")
			}
			clock.Advance(duration)
			o.check(t, 1)
			if e = r.Run(context.Background(), h, b, func(context.Context, *Lease) error { t.Fatal("expired session ran"); return nil }); !errors.Is(e, ErrMissing) {
				t.Fatal("expired session revived")
			}
		})
	}
}
func TestTransitionOnlyOriginalIDAndNeverExtendsDeadline(t *testing.T) {
	r, clock, b, o := fixture(t)
	h, e := r.Install(b, o)
	if e != nil {
		t.Fatal("install failed")
	}
	next := b
	next.TransitionID = "rotation-original"
	next.TransitionHash = b.InitializationProposalHash
	next.ExpiresAt = clock.Now().Unix() + 90
	if e = r.Run(context.Background(), h, b, func(ctx context.Context, l *Lease) error {
		if e := l.Advance(next); e != nil {
			t.Fatal("transition bind failed")
		}
		for _, mutate := range []func(*Binding){func(v *Binding) { v.TransitionID = "replacement" }, func(v *Binding) { v.TransitionHash = string(bytes.Repeat([]byte{'c'}, 64)) }, func(v *Binding) { v.ExpiresAt++ }, func(v *Binding) { v.RecoveryGeneration = "3" }} {
			bad := next
			mutate(&bad)
			if !errors.Is(l.Advance(bad), ErrBinding) {
				t.Fatal("transition replacement accepted")
			}
		}
		shorter := next
		shorter.ExpiresAt--
		if e := l.Advance(shorter); e != nil {
			t.Fatal("deadline tightening rejected")
		}
		next = shorter
		return nil
	}); e != nil {
		t.Fatal("transition operation failed")
	}
	if e = r.Run(context.Background(), h, b, func(context.Context, *Lease) error { t.Fatal("old binding reused"); return nil }); !errors.Is(e, ErrBinding) {
		t.Fatal("old transition reused")
	}
	clock.Advance(90 * time.Second)
	o.check(t, 1)
	if e = r.Run(context.Background(), h, next, func(context.Context, *Lease) error { t.Fatal("expired transition reused"); return nil }); !errors.Is(e, ErrMissing) {
		t.Fatal("transition deadline extended")
	}
}
func TestBusyLogoutAndDisposeCancelActiveOperation(t *testing.T) {
	for _, dispose := range []bool{false, true} {
		t.Run(map[bool]string{false: "logout", true: "dispose"}[dispose], func(t *testing.T) {
			r, _, b, o := fixture(t)
			h, e := r.Install(b, o)
			if e != nil {
				t.Fatal("install failed")
			}
			started := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- r.Run(context.Background(), h, b, func(ctx context.Context, l *Lease) error {
					close(started)
					<-ctx.Done()
					if _, e := l.Owner(); !errors.Is(e, ErrMissing) {
						t.Error("invalidated owner available")
					}
					return ctx.Err()
				})
			}()
			<-started
			if !errors.Is(r.Run(context.Background(), h, b, func(context.Context, *Lease) error { t.Fatal("concurrent operation ran"); return nil }), ErrBusy) {
				t.Fatal("busy not rejected")
			}
			denied := &fixtureOwner{key: bytes.Repeat([]byte{4}, 64)}
			if _, e = r.Install(b, denied); !errors.Is(e, ErrBusy) {
				t.Fatal("busy replacement accepted")
			}
			denied.check(t, 1)
			if dispose {
				r.Close()
			} else {
				r.Clear()
			}
			select {
			case e := <-done:
				if !errors.Is(e, context.Canceled) {
					t.Fatal("active cancellation lost")
				}
			case <-time.After(time.Second):
				t.Fatal("active operation not cancelled")
			}
			o.check(t, 1)
			r.Clear()
			o.check(t, 1)
			if dispose {
				denied = &fixtureOwner{key: bytes.Repeat([]byte{5}, 64)}
				if _, e = r.Install(b, denied); !errors.Is(e, ErrClosed) {
					t.Fatal("disposed registry revived")
				}
				denied.check(t, 1)
			}
		})
	}
}
func TestInvalidInstallClosesIncomingOwner(t *testing.T) {
	r, clock, b, _ := fixture(t)
	for _, mutate := range []func(*Binding){func(v *Binding) { v.Endpoint = "http://synthetic.example.invalid" }, func(v *Binding) { v.AccountGeneration = "01" }, func(v *Binding) { v.ExpiresAt = clock.Now().Unix() }, func(v *Binding) { v.ExpiresAt = clock.Now().Unix() + 306 }, func(v *Binding) { v.TransitionID = "partial" }} {
		invalid := b
		mutate(&invalid)
		o := &fixtureOwner{key: bytes.Repeat([]byte{6}, 64)}
		if _, e := r.Install(invalid, o); !errors.Is(e, ErrBinding) {
			t.Fatal("invalid session installed")
		}
		o.check(t, 1)
	}
}

func TestDeadlineCancelsActiveOwnerAndRejectsUnboundedChallenge(t *testing.T) {
	r, clock, b, o := fixture(t)
	h, e := r.Install(b, o)
	if e != nil {
		t.Fatal("install failed")
	}
	if e = r.Run(context.Background(), h, b, func(ctx context.Context, l *Lease) error {
		next := b
		next.TransitionID = "original"
		next.TransitionHash = b.InitializationProposalHash
		next.ExpiresAt = int64(^uint64(0) >> 1)
		if !errors.Is(l.Advance(next), ErrBinding) {
			t.Fatal("unbounded challenge accepted")
		}
		return nil
	}); e != nil {
		t.Fatal("live operation failed")
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.Run(context.Background(), h, b, func(ctx context.Context, l *Lease) error { close(started); <-ctx.Done(); return ctx.Err() })
	}()
	<-started
	clock.Advance(maxTTL)
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("TTL cancellation lost")
		}
	case <-time.After(time.Second):
		t.Fatal("TTL did not cancel active operation")
	}
	o.check(t, 1)
}

func TestNewProcessRegistryCannotRestoreHandle(t *testing.T) {
	r, _, b, o := fixture(t)
	h, e := r.Install(b, o)
	if e != nil {
		t.Fatal("install failed")
	}
	r.Close()
	o.check(t, 1)
	replacement, _, _, newOwner := fixture(t)
	if _, e = replacement.Install(b, newOwner); e != nil {
		t.Fatal("replacement install failed")
	}
	if e = replacement.Run(context.Background(), h, b, func(context.Context, *Lease) error { t.Fatal("old process handle accepted"); return nil }); !errors.Is(e, ErrMissing) {
		t.Fatal("old process handle restored")
	}
	var restored Handle
	if !errors.Is(json.Unmarshal([]byte(`{}`), &restored), ErrNativeOnly) {
		t.Fatal("native handle decoded")
	}
}

func TestRetirementPreservesAcceptedOrPendingOperationFault(t *testing.T) {
	r, _, b, o := fixture(t)
	h, e := r.Install(b, o)
	if e != nil {
		t.Fatal(e)
	}
	original := errors.New("synthetic accepted not applied")
	e = r.Run(context.Background(), h, b, func(context.Context, *Lease) error { r.Clear(); return original })
	if !errors.Is(e, original) || !errors.Is(e, context.Canceled) {
		t.Fatal("retirement swallowed journal outcome")
	}
	o.check(t, 1)
}

func TestInvalidateCancelsAndRejectsLeaseBeforeDeferredClose(t *testing.T) {
	r, _, b, o := fixture(t)
	h, err := r.Install(b, o)
	if err != nil {
		t.Fatal(err)
	}
	entered, unwind := make(chan context.Context, 1), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.Run(context.Background(), h, b, func(ctx context.Context, l *Lease) error { entered <- ctx; <-unwind; return nil })
	}()
	ctx := <-entered
	r.Invalidate()
	if ctx.Err() == nil {
		t.Fatal("active context not canceled")
	}
	o.check(t, 0)
	if err = r.Run(context.Background(), h, b, func(context.Context, *Lease) error { t.Fatal("invalidated lease executed"); return nil }); !errors.Is(err, ErrMissing) {
		t.Fatal("new lease not rejected", err)
	}
	close(unwind)
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("active result reported success", err)
	}
	r.Clear()
	r.Clear()
	o.check(t, 1)
}
