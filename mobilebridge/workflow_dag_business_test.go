package mobilebridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"

	"encoding/json"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
	"strings"
	"testing"
)

func TestDAGBusinessExactCommandsAndClosedProfiles(t *testing.T) {
	base := `{"version":1,"endpoint":"https://synthetic.example.invalid","operation":"putDAGVariable","requestId":"synthetic-write","environmentId":"synthetic-env","name":"TOKEN"}`
	if e := ValidateDAGBusinessCommand(base); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{
		strings.Replace(base, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(base, `"requestId"`, `"RequestId"`, 1),
		strings.Replace(base, `"TOKEN"`, `"__harmonia_internal"`, 1),
		strings.Replace(base, `"putDAGVariable"`, `"setVariable"`, 1),
		strings.TrimSuffix(base, "}") + `,"value":"SYNTHETIC_VALUE"}`,
		base + "{}",
		base + strings.Repeat(" ", 4096),
	} {
		if ValidateDAGBusinessCommand(raw) == nil {
			t.Fatal("invalid exact DTO accepted")
		}
	}
	p, e := DAGBusinessProfile()
	if e != nil {
		t.Fatal(e)
	}
	var profile struct {
		Version    int
		Profile    string
		Operations []string
	}
	if json.Unmarshal([]byte(p), &profile) != nil || len(profile.Operations) != 4 || profile.Operations[0] != "deleteDAGVariable" {
		t.Fatal("profile")
	}
	ordinary, e := WorkflowProfile()
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(ordinary, "putDAGVariable") {
		t.Fatal("ordinary profile expanded")
	}
}

func TestDAGBusinessUntrustedHasNoViewAndConsumesValues(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	slot := &typedAtomicNativeFixture{}
	v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic-DAG-business", nil, nil, slot)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	for _, input := range []struct {
		op, fields string
		value      []byte
	}{
		{"putDAGVariable", `,"requestId":"synthetic-id","environmentId":"synthetic-env","name":"TOKEN"`, []byte("SYNTHETIC_VALUE")},
		{"deleteDAGVariable", `,"requestId":"synthetic-id","environmentId":"synthetic-env","name":"TOKEN"`, []byte("SYNTHETIC_REJECTED")},
		{"pendingDAGWrites", "", nil},
		{"retryDAGWrite", `,"requestId":"synthetic-id"`, nil},
	} {
		raw := `{"version":1,"endpoint":"https://synthetic.example.invalid","operation":"` + input.op + `"` + input.fields + `}`
		out, e := v.ExecuteDAGBusiness(raw, input.value)
		if e == nil || out != "" || !bytes.Equal(input.value, make([]byte, len(input.value))) {
			t.Fatal("untrusted/secret boundary")
		}
	}
}

// 成熟Writer的真实密文journal元数据再经桥转换；不是手造accepted/sequence DTO。
// 本组件TLS夹具只验证fixed-item槽语义，不声称生产TS或系统认证验收。
func TestDAGBusinessWriterMetadataKeepsFixedItemSequenceSlots(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown-zero-slot", true: "accepted-not-applied-positive-slot"}[accepted], func(t *testing.T) {
			managerPub, managerKey, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			defer clear(managerKey)
			devicePub, deviceKey, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			defer clear(deviceKey)
			recvPub, recvKey, e := cryptox.GenerateReceivingKey()
			if e != nil {
				t.Fatal(e)
			}
			defer clear(recvKey)
			envKey, e := cryptox.GenerateEnvironmentKey()
			if e != nil {
				t.Fatal(e)
			}
			defer clear(envKey)
			grant := cryptox.Grant{AccountID: "synthetic-acct", AccountGeneration: "1", IssuerDeviceID: "synthetic-manager", SubjectDeviceID: "synthetic-dev", SubjectSigningPublicKey: cryptox.EncodeBase64(devicePub), SubjectReceivingPublicKey: cryptox.EncodeBase64(recvPub), EnvironmentID: "synthetic-env", KeyVersion: "1", GrantGeneration: "1", Role: "rw", ExpiresAt: "0", IdempotencyKey: "synthetic-grant"}
			envelope, e := cryptox.WrapEnvironmentKey(envKey, cryptox.EnvelopeContext{AccountID: grant.AccountID, AccountGeneration: "1", EnvironmentID: grant.EnvironmentID, KeyVersion: "1", RecipientType: "device", RecipientID: grant.SubjectDeviceID, RecipientGeneration: "1", RecipientPublicKey: grant.SubjectReceivingPublicKey})
			if e != nil {
				t.Fatal(e)
			}
			grant.Envelope = cryptox.EncodeBase64(envelope)
			signed, e := cryptox.SignGrant(grant, managerKey)
			if e != nil {
				t.Fatal(e)
			}
			verifier, e := syncclient.NewPinnedVerifier(syncclient.PinnedTrust{AccountID: grant.AccountID, AccountGeneration: 1, DeviceID: grant.SubjectDeviceID, DeviceSigningPublicKey: devicePub, ReceivingPrivateKey: recvKey, Managers: map[string]ed25519.PublicKey{grant.IssuerDeviceID: managerPub}})
			if e != nil {
				t.Fatal(e)
			}
			defer verifier.Close()
			engine, e := localstate.New(&dagBusinessMetadataStore{state: localstate.EmptyState()})
			if e != nil {
				t.Fatal(e)
			}
			journal := &dagBusinessMetadataJournal{}
			var posted atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					var mutation syncclient.SignedMutation
					if json.NewDecoder(r.Body).Decode(&mutation) != nil || cryptox.VerifyMutation(cryptox.SignedMutation{Mutation: mutation.Mutation, Signature: mutation.Signature}, devicePub) != nil {
						t.Error("invalid synthetic mutation")
					}
					posted.Store(true)
					if accepted {
						_ = json.NewEncoder(w).Encode(syncclient.Acceptance{Sequence: 2})
					} else {
						w.WriteHeader(504)
						_, _ = w.Write([]byte(`{"error":"request_rejected"}`))
					}
					return
				}
				if posted.Load() {
					w.WriteHeader(503)
					_, _ = w.Write([]byte(`{"error":"request_rejected"}`))
					return
				}
				if strings.HasSuffix(r.URL.Path, "/mutation-status") {
					_ = json.NewEncoder(w).Encode(syncclient.MutationStatus{IdempotencyKey: r.URL.Query().Get("idempotencyKey")})
					return
				}
				_ = json.NewEncoder(w).Encode(syncclient.Pull{AccountID: grant.AccountID, AccountGeneration: "1", Sequence: 1, Grants: []syncclient.SignedGrant{{Grant: signed.Grant, Signature: signed.Signature}}})
			}))
			defer server.Close()
			client, e := syncclient.New(syncclient.Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: grant.AccountID, AccountGeneration: 1, DeviceID: grant.SubjectDeviceID, Token: cryptox.EncodeBase64(make([]byte, 32)), Verifier: verifier, Engine: engine})
			if e != nil {
				t.Fatal(e)
			}
			writer, e := syncclient.NewWriter(grant.AccountID, 1, grant.SubjectDeviceID, engine.State().SessionEpoch, deviceKey, journal)
			if e != nil {
				t.Fatal(e)
			}
			defer writer.Close()
			result, e := writer.Execute(context.Background(), client, syncclient.WriteRequest{ID: "synthetic-request", Operation: "put", EnvironmentID: grant.EnvironmentID, Name: "TOKEN", Value: "SYNTHETIC_VALUE"})
			if result.Applied || e == nil || !posted.Load() || accepted && !errors.Is(e, syncclient.ErrAcceptedNotApplied) || !accepted && !errors.Is(e, syncclient.ErrWritePending) {
				t.Fatal("fixture did not retain actual unknown receipt")
			}
			rows, e := writer.PendingRequests()
			if e != nil || len(rows) != 1 {
				t.Fatal("pending journal", e)
			}
			dto, e := nativeDAGWriteInfo(rows[0])
			if e != nil {
				t.Fatal(e)
			}
			raw, e := json.Marshal(dto)
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(raw, []byte("SYNTHETIC_VALUE")) || bytes.Contains(raw, []byte("TOKEN")) {
				t.Fatal("metadata contains value or name")
			}
			expected, number := "0", 0
			if accepted {
				expected, number = "2", 1
			}
			sequences := dto["sequences"].([]string)
			if dto["accepted"] != number || len(sequences) != 1 || sequences[0] != expected || dto["applied"] != false {
				t.Fatal("actual Writer fixed item slot changed")
			}
		})
	}
}

type dagBusinessMetadataStore struct{ state localstate.State }

func (s *dagBusinessMetadataStore) Load() (localstate.State, error) { return s.state, nil }
func (s *dagBusinessMetadataStore) Save(v localstate.State) error   { s.state = v; return nil }

type dagBusinessMetadataJournal struct {
	mu   sync.Mutex
	data []byte
}

func (j *dagBusinessMetadataJournal) Load() ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.data) == 0 {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(j.data), nil
}
func (j *dagBusinessMetadataJournal) Save(v []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.data = bytes.Clone(v)
	return nil
}
