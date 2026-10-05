package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

func TestPendingPairingsV5AuthenticatedProfileAndResponseBound(t *testing.T) {
	fixture := newManagementFixture(t)
	verifier := fixture.c.config.Verifier.(*PinnedVerifier)
	engine := fixture.c.config.Engine
	cloud := engine.State().Cloud
	var fault, hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		hits.Add(1)
		if r.Method != "GET" || r.URL.RawQuery != "" || !strings.HasSuffix(r.URL.Path, "/pairing-requests-v5") || r.Header.Get("Authorization") == "" || r.Header.Get("X-Harmonia-Device-Id") != fixture.c.config.DeviceID || r.Header.Get("X-Harmonia-Account-Generation") != "1" {
			t.Error("device-bound fixed request contract")
			w.WriteHeader(400)
			return
		}
		out := PendingPairingRequests{AccountGeneration: "1", CertificateVersion: "5", Capabilities: []string{cryptox.RecoveryDAGCapability}, Requests: []PendingPairingRequest{{"pair-request", "new-device", "pending", strconv.FormatInt(int64(2030000000)+60, 10)}}}
		switch fault.Load() {
		case 1:
			out.AccountGeneration = "2"
		case 2:
			out.CertificateVersion = "3"
		case 3:
			out.Capabilities = []string{"issuer-origin-v1"}
		case 4:
			out.Requests = append(out.Requests, out.Requests[0])
		case 5:
			out.Requests[0].ExpiresAt = strconv.FormatInt(int64(2030000000), 10)
		case 6:
			raw, _ := json.Marshal(out)
			w.Write(append(raw, bytes.Repeat([]byte(" "), 65536)...))
			return
		case 7:
			out.Requests = nil
		case 8:
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"admin_required"}`))
			return
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	c, e := New(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: cloud.AccountID, AccountGeneration: 1, DeviceID: fixture.c.config.DeviceID, Token: cryptox.EncodeBase64(bytes.Repeat([]byte{77}, 32)), Verifier: verifier, Engine: engine, Now: func() time.Time { return time.Unix(int64(2030000000), 0) }})
	check(t, e)
	ctx := context.Background()
	out, e := c.PendingPairingRequestsV5(ctx)
	check(t, e)
	if len(out.Requests) != 1 || out.Requests[0].IdempotencyKey != "pair-request" {
		t.Fatal("valid metadata missing")
	}
	for _, kind := range []int32{1, 2, 3, 4, 6, 7, 8} {
		fault.Store(kind)
		if out, e = c.PendingPairingRequestsV5(ctx); e == nil || len(out.Requests) != 0 {
			t.Fatal("invalid scope/bound/permission returned snapshot", kind)
		}
	}
	fault.Store(5)
	out, e = c.PendingPairingRequestsV5(ctx)
	check(t, e)
	if len(out.Requests) != 0 {
		t.Fatal("expired hint retained")
	}
	before := hits.Load()
	check(t, engine.SetPaused(true))
	if _, e = c.PendingPairingRequestsV5(ctx); e == nil || hits.Load() != before {
		t.Fatal("paused cache used for management hint")
	}
}
func TestPendingPairingsVerifiedReadonlySourceZeroRequest(t *testing.T) {
	_, trust, pull := originClientVector(t)
	v, e := NewPinnedVerifierV5(trust)
	check(t, e)
	defer v.Close()
	cloud, e := v.VerifyPull(context.Background(), pull, localstate.CloudSnapshot{})
	check(t, e)
	for _, env := range cloud.Environments {
		if env.Role != localstate.ReadOnly {
			t.Fatal("negative must use genuine RO source")
		}
	}
	engine, e := localstate.New(&volatileStore{state: localstate.EmptyState()})
	check(t, e)
	check(t, engine.AcceptSnapshot(cloud, trust.Now()))
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		hits.Add(1)
		w.WriteHeader(500)
	}))
	defer server.Close()
	c, e := New(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: cloud.AccountID, AccountGeneration: 1, DeviceID: trust.DeviceID, Token: cryptox.EncodeBase64(bytes.Repeat([]byte{77}, 32)), Verifier: v, Engine: engine, Now: trust.Now})
	check(t, e)
	if _, e = c.PendingPairingRequestsV5(context.Background()); e == nil || hits.Load() != 0 {
		t.Fatal("verified RO device listed requests")
	}
}
