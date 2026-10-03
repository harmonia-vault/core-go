package mobileworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

func TestDAGAccountScopeCAS(t *testing.T) {
	var hits atomic.Int32
	token := cryptox.EncodeBase64(bytes.Repeat([]byte{91}, 32))
	account, generation := "synthetic-account", "1"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/login" {
			t.Error("unexpected DAG route")
			w.WriteHeader(500)
			return
		}
		json.NewEncoder(w).Encode(syncclient.LoginResult{AccountID: account, AccountGeneration: generation, Token: token, ExpiresAt: time.Now().Add(time.Hour).Unix()})
	}))
	defer server.Close()
	makeConfig := func() (Config, *dagNativeSlot) {
		c := testConfig(t)
		s := &dagNativeSlot{}
		c.Endpoint = server.URL
		c.HTTPClient = server.Client()
		c.SaveProtectedState = func([]byte) error { t.Fatal("ordinary Save forbidden"); return nil }
		c.SaveProtectedStateCAS = s.cas
		c.CheckProtectedState = s.check
		return c, s
	}
	t.Run("success-persist-scope-and-current-hash-reopen", func(t *testing.T) {
		c, s := makeConfig()
		w, e := New(c)
		if e != nil {
			t.Fatal(e)
		}
		defer w.Close()
		out, e := w.LoginDAGAccountScope(context.Background(), "synthetic@example.invalid", "SYNTHETIC_PASSWORD")
		if e != nil || out.TrustedDevice || out.AccountID != account {
			t.Fatal("scope", e)
		}
		if w.login != nil || w.protectedSHA256 != protectedStateHash(s.read()) {
			t.Fatal("RAM bearer/SHA stale")
		}
		raw := s.read()
		defer clear(raw)
		if bytes.Contains(raw, []byte(token)) || bytes.Contains(raw, []byte("SYNTHETIC_PASSWORD")) {
			t.Fatal("secret persisted")
		}
		b, e := w.dagBindingLocked()
		if e != nil || b.OwnerEpoch != 0 || b.AccountID != account {
			t.Fatal("B1 binding", e)
		}
		c.ProtectedState = raw
		cold, e := New(c)
		if e != nil {
			t.Fatal(e)
		}
		defer cold.Close()
		if cold.state.AccountID != account || cold.state.Root != nil {
			t.Fatal("cold scope trusted/missing")
		}
		if _, e = cold.LoginDAGAccountScope(context.Background(), "synthetic@example.invalid", "SYNTHETIC_PASSWORD"); e != nil {
			t.Fatal("same tuple", e)
		}
		account = "other-synthetic"
		if _, e = cold.LoginDAGAccountScope(context.Background(), "synthetic@example.invalid", "SYNTHETIC_PASSWORD"); !errors.Is(e, ErrDAGOwnerBinding) {
			t.Fatal("account replaced", e)
		}
		account = out.AccountID
		generation = "2"
		if _, e = cold.LoginDAGAccountScope(context.Background(), "synthetic@example.invalid", "SYNTHETIC_PASSWORD"); !errors.Is(e, ErrDAGOwnerBinding) {
			t.Fatal("generation replaced", e)
		}
		generation = "1"
	})
	t.Run("CAS-failure-clears-current-owner-and-no-recovery-route", func(t *testing.T) {
		c, s := makeConfig()
		s.fail = true
		w, e := New(c)
		if e != nil {
			t.Fatal(e)
		}
		defer w.Close()
		start := hits.Load()
		out, e := w.LoginDAGAccountScope(context.Background(), "synthetic@example.invalid", "SYNTHETIC_PASSWORD")
		if !errors.Is(e, ErrDAGPersistence) || out.TrustedDevice || !w.closed || len(w.signing) != 0 || len(w.receiving) != 0 || len(s.read()) != 0 || hits.Load() != start+1 {
			t.Fatal("failed scope leaked/promoted", e)
		}
	})
	t.Run("missing-CAS-check-conflict-closed-zero-HTTP", func(t *testing.T) {
		for _, mode := range []string{"no-cas", "no-check", "changed-native", "closed", "root", "pending", "DAG-journal"} {
			c, s := makeConfig()
			w, e := New(c)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "no-cas" {
				w.saveNativeCAS = nil
			}
			if mode == "no-check" {
				w.checkNativeState = nil
			}
			if mode == "changed-native" {
				s.packet = []byte("synthetic-conflict")
			}
			if mode == "root" {
				w.state.Root = &cryptox.TrustRoot{}
			}
			if mode == "pending" {
				w.state.Pending = &pendingInitialization{}
			}
			if mode == "DAG-journal" {
				w.state.RecoveryDAG = &recoveryDAGState{}
			}
			if mode == "closed" {
				_ = w.engine.Logout()
			}
			before := hits.Load()
			_, e = w.LoginDAGAccountScope(context.Background(), "synthetic@example.invalid", "SYNTHETIC_PASSWORD")
			if e == nil || hits.Load() != before {
				t.Fatal(mode, "not failclosed", e)
			}
			w.Close()
		}
	})
}
