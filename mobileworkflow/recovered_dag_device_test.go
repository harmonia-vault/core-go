package mobileworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/syncclient"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func b3bConfirmedFixture(t *testing.T) (Config, *Workflow, *dagNativeSlot) {
	t.Helper()
	c, w, j, _, next, slot := b3MobileFixture(t)
	if e := j.Save(next); e != nil {
		t.Fatal(e)
	}
	next.Attempted = true
	if e := j.Save(next); e != nil {
		t.Fatal(e)
	}
	n, _ := strconv.ParseUint(next.Recovered.Submission.Enrollment.ExpectedSequence, 10, 64)
	next.AcceptedSequence = n + 1
	if e := j.Save(next); e != nil {
		t.Fatal(e)
	}
	next.Applied = true
	if e := j.Save(next); e != nil {
		t.Fatal(e)
	}
	return c, w, slot
}
func TestB3bUnconfirmedAndLegacyBusinessFailBeforeHTTP(t *testing.T) {
	_, w, j, _, next, _ := b3MobileFixture(t)
	defer w.Close()
	var requests atomic.Int32
	w.http = &http.Client{Transport: b3bRejectTransport{calls: &requests}}
	if e := j.Save(next); e != nil {
		t.Fatal(e)
	}
	if _, e := w.ApplyDAGRecoveredDevice(context.Background(), nil, DAGOwnerScope{}); e == nil {
		t.Fatal("sealed became trusted")
	}
	next.Attempted = true
	_ = j.Save(next)
	n, _ := strconv.ParseUint(next.Recovered.Submission.Enrollment.ExpectedSequence, 10, 64)
	next.AcceptedSequence = n + 1
	_ = j.Save(next)
	if _, e := w.ApplyDAGRecoveredDevice(context.Background(), nil, DAGOwnerScope{}); e == nil {
		t.Fatal("accepted alone became trusted")
	}
	if _, e := w.SetVariable(context.Background(), "synthetic", "TOKEN", "SYNTHETIC_VALUE", "synthetic-put"); !errors.Is(e, ErrRecoveryRestricted) {
		t.Fatal("legacy write", e)
	}
	if requests.Load() != 0 {
		t.Fatal("unexpected HTTP")
	}
}
func TestB3bStrictSourceWrapperAndStickyLogoutCAS(t *testing.T) {
	for _, raw := range []string{`{"Version":1,"profile":"p","original":{}}`, `{"version":1,"profile":"p","original":null}`, `{"version":1,"profile":"p","original":{},"extra":1}`} {
		var r recoveredDAGDeviceRecord
		if json.Unmarshal([]byte(raw), &r) == nil {
			t.Fatal("nonexact source accepted")
		}
	}
	c, w, slot := b3bConfirmedFixture(t)
	before := slot.read()
	var ordinary atomic.Int32
	w.saveNative = func([]byte) error { ordinary.Add(1); return errors.New("ordinary forbidden") }
	if e := w.Logout(); e != nil {
		t.Fatal(e)
	}
	if ordinary.Load() != 0 || !w.closed || bytes.Equal(slot.read(), before) {
		t.Fatal("logout bypassed CAS")
	}
	c.ProtectedState = slot.read()
	c.SaveProtectedStateCAS = nil
	c.CheckProtectedState = nil
	cold, e := New(c)
	if e != nil {
		t.Fatal("closed state read", e)
	}
	defer cold.Close()
	if !cold.requiresDAGCAS || !cold.state.DAGCASRequired {
		t.Fatal("cold logout lost sticky CAS")
	}
	if e = cold.persist(); !errors.Is(e, ErrDAGAtomicStoreRequired) {
		t.Fatal("ordinary Save after closed reopen", e)
	}
}
func TestB3bOwnerRetireBusyAndExactSnapshot(t *testing.T) {
	scope := DAGOwnerScope{Namespace: "synthetic", Slot: "device", PlatformEpoch: 1}
	r, e := NewDAGRecoveryRegistry(scope)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	id := dagOwnerIdentity{DeviceID: "synthetic-device", Snapshot: "synthetic-hash"}
	entry := &dagOwnerEntry{registry: r, identity: id, phase: "device-original-applied", busy: true, closed: make(chan struct{})}
	r.current = entry
	if e = retireAppliedDAGOwner(r, scope, id); !errors.Is(e, ErrDAGQueryBusy) {
		t.Fatal(e)
	}
	entry.busy = false
	bad := id
	bad.Snapshot = "other-hash"
	if e = retireAppliedDAGOwner(r, scope, bad); !errors.Is(e, ErrDAGOwnerBinding) {
		t.Fatal(e)
	}
	if e = retireAppliedDAGOwner(r, scope, id); e != nil {
		t.Fatal(e)
	}
	select {
	case <-entry.closed:
	case <-time.After(time.Second):
		t.Fatal("not drained")
	}
}

func TestB3bInFlightCloseLogoutAndNativeConflict(t *testing.T) {
	for _, action := range []string{"Close", "Logout", "native-conflict"} {
		t.Run(action, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				close(entered)
				select {
				case <-r.Context().Done():
				case <-release:
				}
				rw.WriteHeader(503)
			}))
			defer func() { close(release); server.Close() }()
			c, old, slot := b3bConfirmedFixture(t)
			// 向量只替换native-only endpoint范围；完整账号/双签/原ID/seq/hash不变。
			state := clone(old.state)
			state.Endpoint = server.URL
			state.RecoveryDAG.Endpoint = server.URL
			var journal struct {
				OwnerEpoch uint64                           `json:"ownerEpoch"`
				Operation  syncclient.ProtectedDAGOperation `json:"operation"`
			}
			if json.Unmarshal(state.RecoveryDAG.Journal, &journal) != nil {
				t.Fatal("journal")
			}
			journal.Operation.Endpoint = server.URL
			state.RecoveryDAG.Journal, _ = json.Marshal(journal)
			raw, _ := json.Marshal(state)
			if e := slot.save(raw); e != nil {
				t.Fatal(e)
			}
			old.Close()
			c.Endpoint = server.URL
			c.HTTPClient = server.Client()
			c.ProtectedState = raw
			w, e := New(c)
			if e != nil {
				t.Fatal("rebound synthetic native fixture", e)
			}
			defer w.Close()
			before := slot.read()
			result := make(chan error, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				out, e := w.ApplyDAGRecoveredDevice(ctx, nil, DAGOwnerScope{})
				if out.TrustedDevice {
					result <- errors.New("late trusted result")
					return
				}
				result <- e
			}()
			select {
			case <-entered:
			case e = <-result:
				t.Fatal("operation exited before controlled HTTP", e)
			case <-time.After(30 * time.Second):
				t.Fatal("network never entered")
			}
			if _, e = w.ApplyDAGRecoveredDevice(context.Background(), nil, DAGOwnerScope{}); !errors.Is(e, ErrDAGQueryBusy) {
				t.Fatal("concurrent promotion", e)
			}
			switch action {
			case "Close":
				w.Close()
			case "Logout":
				if e = w.Logout(); e != nil {
					t.Fatal(e)
				}
			case "native-conflict":
				if e = slot.save([]byte("synthetic external newer native state")); e != nil {
					t.Fatal(e)
				}
				cancel()
			}
			select {
			case e = <-result:
				if !errors.Is(e, syncclient.ErrAcceptedNotApplied) {
					t.Fatal("late operation succeeded", e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancel/drain blocked")
			}
			if action == "Close" && !bytes.Equal(before, slot.read()) {
				t.Fatal("Close installed source")
			}
			if action == "Logout" {
				var closed protectedState
				if json.Unmarshal(slot.read(), &closed) != nil || !closed.Cloud.AccountClosed || closed.Root != nil || closed.RecoveredDAGDevice != nil || !closed.DAGCASRequired {
					t.Fatal("Logout resurrected source")
				}
			}
			if action == "native-conflict" && !bytes.Equal(slot.read(), []byte("synthetic external newer native state")) {
				t.Fatal("overwrote foreign checkpoint")
			}
		})
	}
}

// 只记录HTTP是否发生，不读取请求body或任何process environment。
type b3bRejectTransport struct{ calls *atomic.Int32 }

func (tr b3bRejectTransport) RoundTrip(*http.Request) (*http.Response, error) {
	tr.calls.Add(1)
	return nil, errors.New("synthetic unexpected HTTP")
}

func TestB3bStickyCleanMarkerJITScopeAndClosedGate(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/login" {
			t.Error("unexpected nonlogin route")
			rw.WriteHeader(500)
			return
		}
		json.NewEncoder(rw).Encode(syncclient.LoginResult{AccountID: "synthetic-b3b-account", AccountGeneration: "1", Token: "W1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1s", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	}))
	defer server.Close()
	c := testConfig(t)
	c.Endpoint = server.URL
	c.HTTPClient = server.Client()
	slot := &dagNativeSlot{}
	var ordinary atomic.Int32
	c.SaveProtectedState = func([]byte) error { ordinary.Add(1); return errors.New("ordinary forbidden") }
	c.SaveProtectedStateCAS = slot.cas
	c.CheckProtectedState = slot.check
	initial, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	s := clone(initial.state)
	s.DAGCASRequired = true
	s.AccountID = "synthetic-b3b-account"
	s.AccountGeneration = "1"
	raw, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	if e = slot.save(raw); e != nil {
		t.Fatal(e)
	}
	initial.Close()
	c.ProtectedState = raw
	w, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	if !w.requiresDAGCAS {
		t.Fatal("cold marker lost")
	}
	info, e := w.LoginDAGAccountScope(context.Background(), "synthetic@example.invalid", "SYNTHETIC_PASSWORD")
	if e != nil || info.TrustedDevice || ordinary.Load() != 0 || hits.Load() != 1 || !w.state.DAGCASRequired || w.protectedSHA256 != protectedStateHash(slot.read()) {
		t.Fatal("marker JIT scope", e)
	}
	if e = w.Logout(); e != nil {
		t.Fatal(e)
	}
	c.ProtectedState = slot.read()
	w, e = New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	if _, e = w.LoginDAGAccountScope(context.Background(), "synthetic@example.invalid", "SYNTHETIC_PASSWORD"); !errors.Is(e, ErrDAGProtectedState) || hits.Load() != 1 || ordinary.Load() != 0 {
		t.Fatal("closed marker login", e)
	}
}
