package mobilebridge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

func TestPendingPairingsNativeStrictCommandAndProjection(t *testing.T) {
	valid := `{"version":1,"endpoint":"https://synthetic.example.invalid","operation":"pendingPairingRequestsV5"}`
	if ValidatePendingPairingsCommand(valid) != nil {
		t.Fatal("valid command")
	}
	for _, raw := range []string{
		strings.Replace(valid, `"version":1`, `"version":null`, 1),
		strings.Replace(valid, `"version":1`, `"version":2`, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"accountId":"caller-choice"`, 1),
		strings.Replace(valid, "https://", "http://", 1),
		strings.Replace(valid, "pendingPairingRequestsV5", "view", 1),
		strings.Replace(valid, "example.invalid", "example.invalid/?token=synthetic", 1),
	} {
		if ValidatePendingPairingsCommand(raw) == nil {
			t.Fatal("invalid command accepted")
		}
	}
	profile, e := WorkflowProfile()
	if e != nil {
		t.Fatal(e)
	}
	for _, operation := range []string{"pendingPairingRequestsV5"} {
		if strings.Contains(profile, operation) {
			t.Fatal("closed entry added to ordinary profile")
		}
		if _, e := parseWorkflowCommand(strings.Replace(valid, "pendingPairingRequestsV5", operation, 1)); e == nil {
			t.Fatal("ordinary parser opened entry")
		}
	}
	source := syncclient.PendingPairingRequests{AccountGeneration: "1", CertificateVersion: "5", Capabilities: []string{cryptox.RecoveryDAGCapability}, Requests: []syncclient.PendingPairingRequest{{IdempotencyKey: "request-1", InitiatorDeviceID: "device-c", State: "pending", ExpiresAt: "2030000060"}}}
	b := stateBinding{AccountID: "synthetic-account", AccountGeneration: "1", DeviceID: "device-b"}
	out, e := nativePendingPairings(source, b)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	if out["approverDeviceId"] != "device-b" || out["authoritativeForApproval"] != false || len(out) != 7 {
		t.Fatal("invented metadata or authority")
	}
	for _, forbidden := range []string{"sequence", "platform", "name", "token", "signature", "password", "keys"} {
		if _, ok := out[forbidden]; ok {
			t.Fatal("metadata included forbidden field")
		}
	}
	source.Capabilities[0] = "mutated"
	source.Requests[0].IdempotencyKey = "mutated"
	if strings.Contains(string(raw), "mutated") || out["capabilities"].([]string)[0] != cryptox.RecoveryDAGCapability {
		t.Fatal("mutable input retained")
	}
	source.Capabilities[0] = cryptox.RecoveryDAGCapability
	for _, field := range []string{"generation", "duplicate", "capability", "closed"} {
		candidate := source
		candidate.Requests = append([]syncclient.PendingPairingRequest(nil), source.Requests...)
		binding := b
		switch field {
		case "generation":
			candidate.AccountGeneration = "2"
		case "duplicate":
			candidate.Requests = append(candidate.Requests, candidate.Requests[0])
		case "capability":
			candidate.Capabilities = []string{"issuer-origin-v1"}
		case "closed":
			binding.AccountClosed = true
		}
		if _, e := nativePendingPairings(candidate, binding); e == nil {
			t.Fatal("invalid native projection", field)
		}
	}
}

func TestPendingPairingsNativeUntrustedZeroNetworkAndNoCAS(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")
		hits.Add(1)
		w.WriteHeader(500)
	}))
	defer server.Close()
	for _, version := range []string{"3", "4"} {
		d, e := NewDevice()
		if e != nil {
			t.Fatal(e)
		}
		slot := &typedAtomicNativeFixture{}
		v, e := d.OpenAtomicWorkflow(server.URL, "synthetic-p2-captured-slot", nil, nil, slot)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(map[string]any{"version": 1, "endpoint": server.URL, "operation": "pendingPairingRequestsV" + version})
		if out, e := v.ExecutePendingPairings(string(raw)); e == nil || out != "" {
			t.Fatal("untrusted owner returned hint")
		}
		if hits.Load() != 0 || slot.cas != 0 || len(slot.read()) != 0 {
			t.Fatal("untrusted hint performed network or persisted")
		}
		v.Invalidate()
		if out, e := v.ExecutePendingPairings(string(raw)); e == nil || out != "" {
			t.Fatal("invalidated native owner returned hint")
		}
		v.Close()
		d.Close()
	}
}
