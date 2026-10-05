package mobileworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/syncclient"
)

// Two independent owners share a native snapshot. One logs out while the
// other's Boot request is blocked. A late HTTP failure must reach the native
// snapshot check, fail closed, and leave the successful logout untouched.
func TestB3bIndependentForeignLogoutPreventsLateTrust(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	releaseHTTP := func() { releaseOnce.Do(func() { close(release) }) }
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Harmonia-Protocol-Major", "2")

		enteredOnce.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
		case <-release:
		}
		rw.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer func() { releaseHTTP(); server.Close() }()
	c, initial, slot := b3bConfirmedFixture(t)
	state := clone(initial.state)
	state.Endpoint = server.URL
	state.RecoveryDAG.Endpoint = server.URL
	var journal struct {
		OwnerEpoch uint64                           `json:"ownerEpoch"`
		Operation  syncclient.ProtectedDAGOperation `json:"operation"`
	}
	if err := json.Unmarshal(state.RecoveryDAG.Journal, &journal); err != nil {
		t.Fatal(err)
	}
	journal.Operation.Endpoint = server.URL
	var err error
	state.RecoveryDAG.Journal, err = json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = slot.save(raw); err != nil {
		t.Fatal(err)
	}
	initial.Close()
	c.Endpoint, c.HTTPClient, c.ProtectedState = server.URL, server.Client(), raw
	var ordinary atomic.Int32
	c.SaveProtectedState = func([]byte) error {
		ordinary.Add(1)
		return errors.New("synthetic ordinary Save forbidden")
	}
	a, err := New(c)
	if err != nil {
		t.Fatal("owner A", err)
	}
	defer a.Close()
	b, err := New(c)
	if err != nil {
		t.Fatal("owner B", err)
	}
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		view DAGRecoveredView
		err  error
	}
	done := make(chan result, 1)
	go func() { view, e := a.ApplyDAGRecoveredDevice(ctx, nil, DAGOwnerScope{}); done <- result{view, e} }()
	select {
	case <-entered:
	case got := <-done:
		t.Fatal("owner A exited before synthetic HTTP", got.err)
	case <-time.After(30 * time.Second):
		t.Fatal("synthetic HTTP never entered")
	}
	logout := make(chan error, 1)
	go func() { logout <- b.Logout() }()
	select {
	case err = <-logout:
		if err != nil {
			t.Fatal("independent Logout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("independent Logout blocked on other owner's HTTP")
	}
	closedBytes := slot.read()
	var closed protectedState
	if err = json.Unmarshal(closedBytes, &closed); err != nil {
		t.Fatal(err)
	}
	if !closed.Cloud.AccountClosed || closed.Root != nil || closed.RecoveredDAGDevice != nil || closed.RecoveryDAG != nil || !closed.DAGCASRequired {
		t.Fatal("Logout did not commit cleared sticky state")
	}
	if ordinary.Load() != 0 {
		t.Fatal("Logout used ordinary Save")
	}
	releaseHTTP()
	select {
	case got := <-done:
		if got.view.TrustedDevice || !errors.Is(got.err, syncclient.ErrAcceptedNotApplied) || !errors.Is(got.err, ErrDAGPersistence) {
			t.Fatalf("late operation did not fail at changed native snapshot: trusted=%v err=%v", got.view.TrustedDevice, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("late operation did not drain")
	}
	if !bytes.Equal(slot.read(), closedBytes) {
		t.Fatal("late operation rewrote logged-out native state")
	}
	if !a.dagPersistenceFailed {
		t.Fatal("stale owner remained writable")
	}
	c.ProtectedState = closedBytes
	cold, err := New(c)
	if err != nil {
		t.Fatal("cold logout state", err)
	}
	defer cold.Close()
	view, err := cold.RestoreDAGRecoveredDevice()
	if view.TrustedDevice || !errors.Is(err, ErrNotTrusted) || !cold.requiresDAGCAS || ordinary.Load() != 0 {
		t.Fatal("cold logout state regained trust or lost CAS", err)
	}
}
