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

func TestPendingPairingsV4AuthenticatedProfileAndResponseBound(t *testing.T) {
	fixture := recoverySource(t)
	trust := recoveryTrust(t, fixture)
	verifier, e := NewRecoveredDevicePinnedVerifier(trust)
	check(t, e)
	defer verifier.Close()
	own := trust.Accepted.Submission.Grants[0]
	proof := trust.Evidence
	cloud, e := verifier.VerifyPull(context.Background(), Pull{Full: true, AccountID: trust.Trust.AccountID, AccountGeneration: "1", Sequence: trust.Accepted.Sequence, Grants: []SignedGrant{{Grant: own.Grant, Signature: own.Signature}}, IssuerRecoveryEvidence: &proof}, localstate.CloudSnapshot{})
	check(t, e)
	engine, e := localstate.New(&volatileStore{state: localstate.EmptyState()})
	check(t, e)
	check(t, engine.AcceptSnapshot(cloud, time.Unix(fixture.Recovery.Now, 0)))
	var fault, hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != "GET" || r.URL.RawQuery != "" || !strings.HasSuffix(r.URL.Path, "/pairing-requests-v4") || r.Header.Get("Authorization") == "" || r.Header.Get("X-Harmonia-Device-Id") != trust.Trust.DeviceID || r.Header.Get("X-Harmonia-Account-Generation") != "1" {
			t.Error("device-bound fixed request contract")
			w.WriteHeader(400)
			return
		}
		out := PendingPairingRequests{AccountGeneration: "1", CertificateVersion: "4", Capabilities: []string{cryptox.RecoveryAuthorityCapability}, Requests: []PendingPairingRequest{{"pair-request", "new-device", "pending", strconv.FormatInt(fixture.Recovery.Now+60, 10)}}}
		switch fault.Load() {
		case 1:
			out.AccountGeneration = "2"
		case 2:
			out.CertificateVersion = "3"
		case 3:
			out.Capabilities = []string{cryptox.EnvironmentOriginCapability}
		case 4:
			out.Requests = append(out.Requests, out.Requests[0])
		case 5:
			out.Requests[0].ExpiresAt = strconv.FormatInt(fixture.Recovery.Now, 10)
		case 6:
			raw, _ := json.Marshal(out)
			w.Write(append(raw, bytes.Repeat([]byte(" "), 32768)...))
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
	c, e := New(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: cloud.AccountID, AccountGeneration: 1, DeviceID: trust.Trust.DeviceID, Token: cryptox.EncodeBase64(bytes.Repeat([]byte{77}, 32)), Verifier: verifier, Engine: engine, Now: func() time.Time { return time.Unix(fixture.Recovery.Now, 0) }})
	check(t, e)
	ctx := context.Background()
	out, e := c.PendingPairingRequestsV4(ctx)
	check(t, e)
	if len(out.Requests) != 1 || out.Requests[0].IdempotencyKey != "pair-request" {
		t.Fatal("valid metadata missing")
	}
	for _, kind := range []int32{1, 2, 3, 4, 6, 7, 8} {
		fault.Store(kind)
		if out, e = c.PendingPairingRequestsV4(ctx); e == nil || len(out.Requests) != 0 {
			t.Fatal("invalid scope/bound/permission returned snapshot", kind)
		}
	}
	fault.Store(5)
	out, e = c.PendingPairingRequestsV4(ctx)
	check(t, e)
	if len(out.Requests) != 0 {
		t.Fatal("expired hint retained")
	}
	before := hits.Load()
	if _, e = c.PendingPairingRequestsV3(ctx); e == nil || hits.Load() != before {
		t.Fatal("proof3 silently fell back to version3")
	}
	check(t, engine.SetPaused(true))
	if _, e = c.PendingPairingRequestsV4(ctx); e == nil || hits.Load() != before {
		t.Fatal("paused cache used for management hint")
	}
}
func TestPendingPairingsVerifiedReadonlySourceZeroRequest(t *testing.T) {
	_, trust, pull := originClientVector(t)
	v, e := NewPinnedVerifierV3(trust)
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
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	c, e := New(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: cloud.AccountID, AccountGeneration: 1, DeviceID: trust.DeviceID, Token: cryptox.EncodeBase64(bytes.Repeat([]byte{77}, 32)), Verifier: v, Engine: engine, Now: trust.Now})
	check(t, e)
	if _, e = c.PendingPairingRequestsV3(context.Background()); e == nil || hits.Load() != 0 {
		t.Fatal("verified RO device listed requests")
	}
}
