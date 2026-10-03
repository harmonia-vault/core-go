package mobileworkflow

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
)

func dagQueryCode(t *testing.T) []byte {
	t.Helper()
	seed, err := cryptox.GenerateRecoverySeed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	code, err := cryptox.EncodeRecoveryCode(seed)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(code)
}

func TestDAGQueryPreflightNoNetworkOrInputRetention(t *testing.T) {
	for _, mode := range []string{"no-original", "save-only", "closed", "stale-native", "canceled", "malformed-code"} {
		t.Run(mode, func(t *testing.T) {
			_, w, j, p, slot := dagMobileFixture(t)
			if err := j.Save(p); err != nil {
				t.Fatal(err)
			}
			var dials atomic.Int32
			w.http = &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("synthetic forbidden network")
			}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			code := dagQueryCode(t)
			switch mode {
			case "no-original":
				w.state.RecoveryDAG = nil
			case "save-only":
				w.saveNativeCAS = nil
			case "closed":
				w.Close()
			case "stale-native":
				if err := slot.save([]byte("synthetic newer snapshot")); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				cancel()
			case "malformed-code":
				clear(code)
				code = []byte("synthetic invalid code")
			}
			result, err := w.QueryRecoveryDAGOriginal(ctx, code)
			if err == nil || result.Observation != "unknown" || result.TrustedDevice || !result.RotationRequired || dials.Load() != 0 || !bytes.Equal(code, make([]byte, len(code))) {
				t.Fatal("preflight opened a capability, network or retained code", err, dials.Load())
			}
		})
	}
}

func TestDAGQueryBusyCloseAndLogoutCancelInFlight(t *testing.T) {
	for _, mode := range []string{"close", "logout"} {
		t.Run(mode, func(t *testing.T) {
			_, w, j, p, slot := dagMobileFixture(t)
			if err := j.Save(p); err != nil {
				t.Fatal(err)
			}
			before := slot.read()
			entered := make(chan struct{}, 1)
			w.http = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				entered <- struct{}{}
				<-ctx.Done()
				return nil, ctx.Err()
			}}}
			done := make(chan error, 1)
			go func() { _, err := w.QueryRecoveryDAGOriginal(context.Background(), dagQueryCode(t)); done <- err }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("query did not start")
			}
			if _, err := w.QueryRecoveryDAGOriginal(context.Background(), dagQueryCode(t)); !errors.Is(err, ErrDAGQueryBusy) {
				t.Fatal("concurrent query was not refused", err)
			}
			if mode == "close" {
				w.Close()
			} else if err := w.Logout(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled query succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("lifecycle did not promptly cancel query")
			}
			if mode == "close" && !bytes.Equal(before, slot.read()) {
				t.Fatal("Close erased original journal")
			}
			if j.OwnerAlive() == nil {
				t.Fatal("retired owner remained live")
			}
		})
	}
}

func TestDAGQueryPortDetachDrainAndCanceledLease(t *testing.T) {
	_, _, j, original, slot := dagMobileFixture(t)
	if err := j.Save(original); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := &dagQueryPort{ctx: ctx, journal: j}
	entered, release := make(chan struct{}), make(chan struct{})
	slot.entered, slot.resume = entered, release
	updated := original
	updated.Attempted = true
	saved, detached := make(chan error, 1), make(chan struct{})
	go func() { saved <- port.Save(updated) }()
	<-entered
	go func() { port.detach(); close(detached) }()
	select {
	case <-detached:
		t.Fatal("detach bypassed active callback")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-saved; err != nil {
		t.Fatal(err)
	}
	select {
	case <-detached:
	case <-time.After(3 * time.Second):
		t.Fatal("detach did not drain")
	}
	if port.OwnerAlive() == nil || port.Save(updated) == nil {
		t.Fatal("detached port retained authority")
	}
	if _, err := port.Load(); err == nil {
		t.Fatal("detached port loaded")
	}
	port = &dagQueryPort{ctx: ctx, journal: j}
	cancel()
	before := slot.read()
	if port.OwnerAlive() == nil || port.Save(updated) == nil {
		t.Fatal("canceled lease retained authority")
	}
	if !bytes.Equal(before, slot.read()) {
		t.Fatal("canceled lease saved")
	}
}
