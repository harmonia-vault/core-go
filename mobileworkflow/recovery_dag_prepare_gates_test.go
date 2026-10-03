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

// This is a gate component fixture, not another TS/SQLite recovery scenario.
// Login follows the public Workflow.Login path over fixture-verified TLS. The
// public signed vector provides a separately validated preparation; no fake
// trusted-device flag, native authentication result or long-lived owner is used.
func TestMobileDAGPreparationLegacyGatesWithLiveLogin(t *testing.T) {
	for _, phase := range []string{"intent", "prepared"} {
		t.Run(phase, func(t *testing.T) {
			c, initial, _, original, slot := b2MobileFixture(t)
			initial.Close()
			var requests, saves, cas atomic.Int32
			login := syncclient.LoginResult{AccountID: original.AccountID, AccountGeneration: original.Pin.AccountGeneration, Token: cryptox.EncodeBase64(bytes.Repeat([]byte{23}, 32)), ExpiresAt: time.Now().Unix() + 300}
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, in *http.Request) {
				requests.Add(1)
				out.Header().Set("Content-Type", "application/json")
				if in.Method == "POST" && in.URL.Path == "/v1/login" {
					_ = json.NewEncoder(out).Encode(login)
					return
				}
				// A bypass remains observable but cannot install old recovery state.
				out.WriteHeader(http.StatusConflict)
				_, _ = out.Write([]byte(`{"error":"synthetic_gate_probe"}`))
			}))
			defer server.Close()
			c.Endpoint = server.URL
			c.HTTPClient = server.Client()
			c.SaveProtectedState = func(raw []byte) error { saves.Add(1); return slot.save(raw) }
			c.SaveProtectedStateCAS = func(expected string, raw []byte) error { cas.Add(1); return slot.cas(expected, raw) }
			w, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if err = w.Login(context.Background(), "gate@example.invalid", "synthetic-gate-password"); err != nil {
				t.Fatal("valid Login prerequisite", err)
			}
			if requests.Load() != 1 || w.login == nil || *w.login != login || w.login.ExpiresAt <= w.now().Unix() {
				t.Fatal("missing actual Login result prerequisite")
			}
			original.Endpoint = server.URL
			prepared := b2Preparation(t, original)
			prepared.Challenge.ExpiresAt = time.Now().Unix() + 60
			store, err := w.newDAGPreparationStore()
			if err != nil {
				t.Fatal(err)
			}
			if err = store.SaveTransitionPreparation(b2Intent(prepared)); err != nil {
				t.Fatal(err)
			}
			if phase == "prepared" {
				if err = store.SaveTransitionPreparation(prepared); err != nil {
					t.Fatal(err)
				}
			}
			metadata, err := w.RecoveryDAGPreparationInfo()
			if err != nil || metadata.Phase != phase || !metadata.NeedsOriginalOwner {
				t.Fatal("valid durable preparation prerequisite", err)
			}
			seed := bytes.Repeat([]byte{31}, 32)
			code, err := cryptox.EncodeRecoveryCode(seed)
			clear(seed)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := cryptox.DecodeRecoveryCode(code)
			clear(decoded)
			if err != nil {
				t.Fatal("complete code format prerequisite", err)
			}
			before := slot.read()
			beforeRequests, beforeSaves, beforeCAS := requests.Load(), saves.Load(), cas.Load()
			calls := map[string]func() error{
				"recovery-info":          func() error { _, e := w.RecoveryInfo(); return e },
				"enrollment-info":        func() error { _, e := w.EnrollmentInfo(); return e },
				"resume-enrollment":      func() error { _, e := w.ResumeEnrollment(context.Background(), "synthetic-original-pairing"); return e },
				"begin-recovery":         func() error { _, e := w.BeginRecovery(context.Background(), code); return e },
				"begin-recovery-origins": func() error { _, e := w.BeginRecoveryWithOrigins(context.Background(), code); return e },
				"begin-recovery-origins-session": func() error {
					s, _, e := w.BeginRecoveryWithOriginsSession(context.Background(), code)
					if s != nil {
						s.Close()
					}
					return e
				},
				"begin-recovery-authority": func() error {
					s, _, e := w.BeginRecoveryAuthoritySession(context.Background(), code)
					if s != nil {
						s.Close()
					}
					return e
				},
			}
			for name, call := range calls {
				t.Run(name, func(t *testing.T) {
					if w.login == nil || *w.login != login || w.login.ExpiresAt <= w.now().Unix() {
						t.Fatal("valid same-instance Login no longer present")
					}
					start := requests.Load()
					if err := call(); !errors.Is(err, ErrRecoveryRestricted) {
						t.Error("preparation did not block legacy entry with ErrRecoveryRestricted")
					}
					if requests.Load() != start {
						t.Error("legacy entry issued HTTP while preparation exists")
					}
					if saves.Load() != beforeSaves || cas.Load() != beforeCAS || !bytes.Equal(before, slot.read()) {
						t.Error("legacy entry saved or changed protected preparation")
					}
				})
			}
			if requests.Load() != beforeRequests {
				t.Error("legacy probes were not zero HTTP")
			}
			t.Logf("LEGACY_GATE_COUNTS phase=%s loginRequests=1 legacyRequests=%d ordinarySaves=%d cas=%d", phase, requests.Load()-beforeRequests, saves.Load()-beforeSaves, cas.Load()-beforeCAS)
			// Cold metadata must report the preparation through its typed API; the old
			// Info APIs must reject, rather than falsely returning an empty none state.
			c.ProtectedState = slot.read()
			cold, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Close()
			for name, call := range map[string]func() error{"cold-recovery-info": func() error { _, e := cold.RecoveryInfo(); return e }, "cold-enrollment-info": func() error { _, e := cold.EnrollmentInfo(); return e }} {
				t.Run(name, func(t *testing.T) {
					start := requests.Load()
					if err := call(); !errors.Is(err, ErrRecoveryRestricted) {
						t.Error("cold old Info hid preparation")
					}
					if requests.Load() != start || saves.Load() != beforeSaves || cas.Load() != beforeCAS || !bytes.Equal(before, slot.read()) {
						t.Error("cold old Info caused HTTP or save")
					}
				})
			}
		})
	}
}
