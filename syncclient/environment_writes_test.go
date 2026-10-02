package syncclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

func environmentWrapperChange(t *testing.T) cryptox.SignedEnvironmentChange {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	signed, err := cryptox.SignEnvironmentChange(cryptox.EnvironmentChange{AccountID: "acct", AccountGeneration: "1", DeviceID: "dev", EnvironmentID: "env", Operation: "delete", AuthorityEnvironmentID: "env", AuthorityKeyVersion: "1", AuthorityGrantGeneration: "1", PreviousKeyVersion: "1", KeyVersion: "1", ExpectedSequence: "7", IdempotencyKey: "env-write", RecoveryGeneration: "1"}, key)
	check(t, err)
	return signed
}

// 仅隔离HTTP wrapper检查点合同；真实Ed/HPKE环境生命周期另有实际HTTPS验收。
type environmentWrapperVerifier struct {
	signed         cryptox.SignedEnvironmentChange
	missing, wrong bool
}

func (v environmentWrapperVerifier) VerifyPull(_ context.Context, pull Pull, _ localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	snapshot := localstate.CloudSnapshot{AccountID: "acct", AccountGeneration: 1, Sequence: pull.Sequence, Environments: map[string]localstate.Environment{"env": {ID: "env", KeyVersion: 1, GrantGeneration: 1, Role: localstate.Admin, Values: map[string]string{"TOKEN": "current-value-is-not-a-receipt"}}}}
	if !v.missing {
		wire, _ := v.signed.Change.SigningBytes()
		hash := digest(wire)
		if v.wrong {
			hash = "wrong"
		}
		snapshot.EnvironmentCheckpoints = map[string]localstate.MutationCheckpoint{"dev/env-write": {Sequence: 8, Fingerprint: hash}}
	}
	return snapshot, nil
}
func TestEnvironmentWrapperBindingPauseAndPinnedSignatureBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	client := testClient(t, server, testEngine(t), acceptVerifier{})
	signed := environmentWrapperChange(t)
	for _, field := range []string{"account", "generation", "device"} {
		other := signed
		switch field {
		case "account":
			other.Change.AccountID = "other"
		case "generation":
			other.Change.AccountGeneration = "2"
		case "device":
			other.Change.DeviceID = "other"
		}
		if _, err := client.SubmitEnvironmentChange(context.Background(), other); err == nil {
			t.Fatal("unbound submit", field)
		}
		if _, err := client.ConfirmEnvironmentChange(context.Background(), other, Acceptance{Sequence: 8}); err == nil {
			t.Fatal("unbound confirmation", field)
		}
	}
	check(t, client.config.Engine.SetPaused(true))
	if _, err := client.SubmitEnvironmentChange(context.Background(), signed); !errors.Is(err, ErrPaused) {
		t.Fatal(err)
	}
	if _, err := client.ConfirmEnvironmentChange(context.Background(), signed, Acceptance{Sequence: 8}); !errors.Is(err, ErrPaused) {
		t.Fatal(err)
	}
	pinned := newCryptoFixture(t)
	client = testClient(t, server, testEngine(t), pinned.verifier)
	if _, err := client.SubmitEnvironmentChange(context.Background(), signed); err == nil {
		t.Fatal("signature by unrelated private key accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("invalid request reached network")
	}
}
func TestEnvironmentWrapperRequiresExactVerifiedReceiptAndSequence(t *testing.T) {
	signed := environmentWrapperChange(t)
	for _, test := range []struct {
		name           string
		missing, wrong bool
		sequence       uint64
		applied        bool
	}{{"verified", false, false, 8, true}, {"only-current-value", true, false, 8, false}, {"wrong-payload", false, true, 8, false}, {"wrong-receipt-sequence", false, false, 9, false}} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(Pull{AccountID: "acct", AccountGeneration: "1", Sequence: 9})
			}))
			defer server.Close()
			client := testClient(t, server, testEngine(t), environmentWrapperVerifier{signed, test.missing, test.wrong})
			result, err := client.ConfirmEnvironmentChange(context.Background(), signed, Acceptance{Sequence: test.sequence})
			if result.Applied != test.applied || test.applied && err != nil || !test.applied && !errors.Is(err, ErrAcceptedNotApplied) {
				t.Fatal(result, err)
			}
		})
	}
}
func TestEnvironmentStatusRejectsInvalidShapesAndBindsHeaders(t *testing.T) {
	for _, status := range []EnvironmentChangeStatus{{State: "complete", Sequence: 8}, {State: "unknown"}, {State: "complete"}, {State: "unknown", Sequence: 8}, {State: "complete", Sequence: 9007199254740992}, {State: "pending"}} {
		t.Run(status.State+"/"+strconv.FormatUint(status.Sequence, 10), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Harmonia-Device-Id") != "dev" || r.Header.Get("X-Harmonia-Account-Generation") != "1" || r.Header.Get("Cache-Control") != "no-store" {
					t.Error("status request lost device binding")
				}
				_ = json.NewEncoder(w).Encode(status)
			}))
			defer server.Close()
			client := testClient(t, server, testEngine(t), acceptVerifier{})
			_, err := client.EnvironmentStatus(context.Background(), "env-write")
			valid := status.State == "complete" && status.Sequence == 8 || status.State == "unknown" && status.Sequence == 0
			if valid != (err == nil) {
				t.Fatal("invalid status accepted or valid status rejected", status, err)
			}
			if _, err := client.EnvironmentStatus(context.Background(), "../other"); err == nil {
				t.Fatal("path injection accepted")
			}
		})
	}
}
