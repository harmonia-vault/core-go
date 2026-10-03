package mobileworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

type b1Timer struct {
	stopped atomic.Bool
	fn      func()
}

func (t *b1Timer) Stop() bool { return !t.stopped.Swap(true) }

type b1Clock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*b1Timer
}

func (c *b1Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *b1Clock) After(_ time.Duration, fn func()) dagOwnerTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &b1Timer{fn: fn}
	c.timers = append(c.timers, t)
	return t
}
func (c *b1Clock) shift(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }
func (c *b1Clock) fire() {
	c.mu.Lock()
	timers := append([]*b1Timer(nil), c.timers...)
	c.mu.Unlock()
	for _, timer := range timers {
		if !timer.stopped.Load() {
			timer.fn()
		}
	}
}

type b1Session struct {
	binding          syncclient.DAGRecoveryBinding
	port             *dagOwnerPort
	closed           atomic.Int32
	entered, release chan struct{}
}

func (s *b1Session) VerifiedBinding() (syncclient.DAGRecoveryBinding, error) {
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	if err := s.port.OwnerAlive(); err != nil {
		return syncclient.DAGRecoveryBinding{}, err
	}
	return s.binding, nil
}
func (s *b1Session) Info() (syncclient.DAGRecoveryInfo, error) {
	if err := s.port.OwnerAlive(); err != nil {
		return syncclient.DAGRecoveryInfo{}, err
	}
	return syncclient.DAGRecoveryInfo{RotationRequired: true, ExpiresAt: s.binding.ExpiresAt}, nil
}
func (s *b1Session) Close() { s.closed.Add(1) }
func b1OwnerFixture(t *testing.T) (Config, *Workflow, *dagNativeSlot, *DAGRecoveryRegistry, *dagOwnerEntry, *b1Session, *b1Clock, DAGOwnerScope) {
	t.Helper()
	c, w, _, _, slot := dagMobileFixture(t)
	// 固定元数据组件夹具；不冒充真实 code/HTTPS/系统认证。
	w.mu.Lock()
	if err := w.persist(); err != nil {
		t.Fatal(err)
	}
	w.mu.Unlock()
	scope := DAGOwnerScope{Namespace: "synthetic-native", Slot: "b1", PlatformEpoch: 17}
	clock := &b1Clock{now: time.Now()}
	r, err := newDAGRecoveryRegistry(scope, clock.Now, clock.After)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	e, ctx, err := r.acquire(context.Background(), scope, true)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := w.attachDAGOwner(e.invalidate)
	if err != nil {
		t.Fatal(err)
	}
	e.identity = identity
	j, err := w.newRecoveryDAGJournal()
	if err != nil {
		t.Fatal(err)
	}
	target := &dagOwnerTarget{e, ctx, j}
	if err = e.port.attach(target); err != nil {
		t.Fatal(err)
	}
	b := syncclient.DAGRecoveryBinding{Profile: cryptox.RecoveryDAGCapability, Endpoint: identity.Binding.Endpoint, AccountID: identity.Binding.AccountID, AccountGeneration: identity.Binding.AccountGeneration, RotationRequired: true, ExpiresAt: clock.Now().Unix() + 900, SessionHash: "synthetic-binding-digest"}
	s := &b1Session{binding: b, port: &e.port}
	e.session = s
	e.binding = b
	if err = e.port.detach(target); err != nil {
		t.Fatal(err)
	}
	w.detachDAGOwner()
	if err = r.finish(e, ctx, nil); err != nil {
		t.Fatal(err)
	}
	return c, w, slot, r, e, s, clock, scope
}
func TestDAGOwnerTwoWorkflowLeaseDoesNotRetainFirst(t *testing.T) {
	c, w, slot, r, e, s, _, scope := b1OwnerFixture(t)
	before := slot.read()
	deadline := e.deadline
	if _, err := w.RecoveryDAGOwnerInfo(context.Background(), r, scope); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if s.closed.Load() != 0 {
		t.Fatal("idle owner retained first Workflow close")
	}
	c.ProtectedState = slot.read()
	second, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	info, err := second.RecoveryDAGOwnerInfo(context.Background(), r, scope)
	if err != nil || !info.RotationRequired || info.TrustedDevice || !e.deadline.Equal(deadline) || !bytes.Equal(before, slot.read()) {
		t.Fatal("second authenticated snapshot or fixed deadline failed", err)
	}
	if e.port.target != nil || second.dagOwnerCancel != nil {
		t.Fatal("idle owner retained lease Workflow")
	}
	if _, err = w.RecoveryDAGOwnerInfo(context.Background(), r, scope); err == nil {
		t.Fatal("closed first Workflow attached")
	}
	if s.closed.Load() != 1 {
		t.Fatal("failed attach did not retire owner once")
	}
}
func TestDAGOwnerRejectsScopeIdentityAndFreshQueryPromotion(t *testing.T) {
	for _, mode := range []string{"namespace", "slot", "platform-epoch", "account", "generation", "device", "snapshot", "pin", "session", "head", "rotation", "sealed-original"} {
		t.Run(mode, func(t *testing.T) {
			_, w, slot, r, _, s, _, scope := b1OwnerFixture(t)
			switch mode {
			case "namespace":
				scope.Namespace += "-other"
			case "slot":
				scope.Slot += "-other"
			case "platform-epoch":
				scope.PlatformEpoch++
			case "account":
				w.state.AccountID = "other-account"
			case "generation":
				w.state.AccountGeneration = "2"
			case "device":
				w.state.DeviceID = "other-device"
			case "snapshot":
				if err := slot.save([]byte("synthetic changed native bytes")); err != nil {
					t.Fatal(err)
				}
			case "pin":
				s.binding.Pin.DeviceID = "other-pin"
			case "session":
				s.binding.SessionHash = "other-session"
			case "head":
				s.binding.RecoveryHeadHash = "other-head"
			case "rotation":
				s.binding.RotationRequired = false
			case "sealed-original":
				w.state.RecoveryDAG = &recoveryDAGState{}
			}
			if info, err := w.RecoveryDAGOwnerInfo(context.Background(), r, scope); err == nil || info.TrustedDevice {
				t.Fatal("substitution accepted")
			}
		})
	}
	_, w, j, p, _ := dagMobileFixture(t)
	if err := j.Save(p); err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	w.http = &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("forbidden")
	}}}
	scope := DAGOwnerScope{Namespace: "synthetic", Slot: "promotion"}
	r, _ := NewDAGRecoveryRegistry(scope)
	defer r.Close()
	if _, err := w.OpenDAGRecoveryOwner(context.Background(), r, scope, dagQueryCode(t)); err == nil || dials.Load() != 0 {
		t.Fatal("fresh-query original promoted or network used")
	}
}
func TestDAGOwnerActiveCancelDrainAndExactlyOnceClose(t *testing.T) {
	for _, mode := range []string{"clear", "close", "workflow-close", "logout", "ttl", "parent-cancel"} {
		t.Run(mode, func(t *testing.T) {
			_, w, _, r, e, s, clock, scope := b1OwnerFixture(t)
			s.entered, s.release = make(chan struct{}), make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := w.RecoveryDAGOwnerInfo(ctx, r, scope); done <- err }()
			select {
			case <-s.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("lease did not start")
			}
			if _, err := w.RecoveryDAGOwnerInfo(context.Background(), r, scope); !errors.Is(err, ErrDAGQueryBusy) {
				t.Fatal("busy lease accepted", err)
			}
			if _, err := w.QueryRecoveryDAGOriginal(context.Background(), dagQueryCode(t)); !errors.Is(err, ErrDAGQueryBusy) {
				t.Fatal("S2a bypassed active owner", err)
			}
			switch mode {
			case "clear":
				r.Clear()
			case "close":
				r.Close()
			case "workflow-close":
				w.Close()
			case "logout":
				if err := w.Logout(); err != nil {
					t.Fatal(err)
				}
			case "ttl":
				clock.shift(5 * time.Minute)
				clock.fire()
			case "parent-cancel":
				cancel()
			}
			if s.closed.Load() != 0 {
				t.Fatal("Close ran while session call held")
			}
			close(s.release)
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled lease succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("lease failed to drain")
			}
			if !e.retired.Load() || s.closed.Load() != 1 || e.port.target != nil {
				t.Fatal("retire/detach/close order failed")
			}
			r.Clear()
			r.Close()
			if s.closed.Load() != 1 {
				t.Fatal("Close ran twice")
			}
		})
	}
}
func TestDAGOwnerIdleTTLAndWallRollback(t *testing.T) {
	for _, mode := range []string{"idle-timer", "elapsed", "wall-back", "server-shorter"} {
		t.Run(mode, func(t *testing.T) {
			_, w, _, r, e, s, clock, scope := b1OwnerFixture(t)
			switch mode {
			case "idle-timer":
				clock.shift(5 * time.Minute)
				clock.fire()
			case "elapsed":
				clock.shift(5 * time.Minute)
			case "wall-back":
				clock.shift(-time.Second)
			case "server-shorter":
				_, ctx, err := r.acquire(context.Background(), scope, false)
				if err != nil {
					t.Fatal(err)
				}
				if err = r.pinDeadline(e, clock.Now().Unix()+60); err != nil {
					t.Fatal(err)
				}
				short := e.deadline
				if err = r.pinDeadline(e, clock.Now().Unix()+900); err != nil {
					t.Fatal(err)
				}
				if !short.Equal(e.deadline) {
					t.Fatal("deadline extended")
				}
				if err = r.finish(e, ctx, nil); err != nil {
					t.Fatal(err)
				}
				clock.shift(61 * time.Second)
			}
			if _, err := w.RecoveryDAGOwnerInfo(context.Background(), r, scope); err == nil {
				t.Fatal("expired owner attached")
			}
			if s.closed.Load() != 1 {
				t.Fatal("idle/expired cleanup missing")
			}
		})
	}
}
func TestDAGOwnerRegistryOpaqueZeroAndRestart(t *testing.T) {
	_, w, _, r, _, s, _, scope := b1OwnerFixture(t)
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("registry serialized")
	}
	if json.Unmarshal([]byte(`{}`), r) == nil {
		t.Fatal("registry deserialized")
	}
	var zero DAGRecoveryRegistry
	if _, err := w.RecoveryDAGOwnerInfo(context.Background(), &zero, scope); err == nil {
		t.Fatal("zero registry usable")
	}
	fresh, _ := NewDAGRecoveryRegistry(scope)
	defer fresh.Close()
	if _, err := w.RecoveryDAGOwnerInfo(context.Background(), fresh, scope); err == nil {
		t.Fatal("new process restored RAM owner")
	}
	r.Clear()
	if s.closed.Load() != 1 {
		t.Fatal("idle cleanup")
	}
	next, ctx, err := r.acquire(context.Background(), scope, true)
	if err != nil {
		t.Fatal("closed owner blocked fresh explicit open", err)
	}
	if err = r.finish(next, ctx, errors.New("synthetic stop")); err == nil {
		t.Fatal("cleanup error hidden")
	}
}

func TestDAGOwnerOpenNetworkFailureRetiresWithoutPartialSession(t *testing.T) {
	_, w, slot, old, _, _, _, scope := b1OwnerFixture(t)
	old.Close()
	before := slot.read()
	var calls atomic.Int32
	w.http = &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("synthetic discovery unavailable")
	}}}
	r, _ := NewDAGRecoveryRegistry(scope)
	defer r.Close()
	code := dagQueryCode(t)
	info, err := w.OpenDAGRecoveryOwner(context.Background(), r, scope, code)
	if err == nil || !info.RotationRequired || info.TrustedDevice || calls.Load() != 1 || !bytes.Equal(code, make([]byte, len(code))) || !bytes.Equal(before, slot.read()) {
		t.Fatal("partial Open failed cleanup or input retention", err)
	}
	if r.current == nil || !r.current.retired.Load() || r.current.session != nil || r.current.port.target != nil {
		t.Fatal("failed Open retained partial session/lease")
	}
	select {
	case <-r.current.closed:
	default:
		t.Fatal("failed Open did not finish exactly-once retirement")
	}
}
