package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/pairing"
)

type issuerClientFixture struct {
	Approval                cryptox.EnrollmentApprovalV2 `json:"approval"`
	HistoricalMutation      cryptox.SignedMutation       `json:"historicalMutation"`
	HistoricalAuthorization cryptox.SignedGrantWire      `json:"historicalAuthorization"`
}

func issuerClientVector(t *testing.T) issuerClientFixture {
	t.Helper()
	data, err := os.ReadFile("../cryptox/testdata/issuer-proof-v1.json")
	check(t, err)
	var f issuerClientFixture
	check(t, json.Unmarshal(data, &f))
	return f
}
func issuerClientTrust(t *testing.T, f issuerClientFixture) IssuerPinnedTrust {
	t.Helper()
	return IssuerPinnedTrust{AccountID: "account-chain", AccountGeneration: 1, DeviceID: "device-C", DeviceSigningPublicKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)).Public().(ed25519.PublicKey), ReceivingPrivateKey: bytes.Repeat([]byte{13}, 32), Receipt: EnrollmentReceiptV2{IdempotencyKey: "pair-C", Approval: f.Approval}, Now: func() time.Time { return time.Unix(2030000000, 0) }}
}
func issuerClientPull(f issuerClientFixture) Pull {
	auth := SignedGrant{Grant: f.HistoricalAuthorization.Grant, Signature: f.HistoricalAuthorization.Signature}
	return Pull{Full: true, Sequence: 1, AccountID: "account-chain", AccountGeneration: "1", Grants: []SignedGrant{{Grant: f.Approval.Grants[0].Grant, Signature: f.Approval.Grants[0].Signature}}, Events: []Event{{Sequence: 1, Mutation: SignedMutation{Mutation: f.HistoricalMutation.Mutation, Signature: f.HistoricalMutation.Signature}, Authorization: &auth}}}
}
func TestIssuerScopedVerifierReadsTwoManagersAndRejectsExpansion(t *testing.T) {
	f := issuerClientVector(t)
	v, err := NewPinnedVerifierV2(issuerClientTrust(t, f))
	check(t, err)
	defer v.Close()
	if len(v.trust.Managers) != 0 || len(v.IssuerBindings()) != 2 {
		t.Fatal("v2 constructed global managers")
	}
	pull := issuerClientPull(f)
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	defer clear(b)
	mutation := f.HistoricalMutation.Mutation
	mutation.DeviceID = "device-B"
	mutation.Name = "B_VALUE"
	mutation.IdempotencyKey = "B-write"
	payload, err := cryptox.EncryptValue(bytes.Repeat([]byte{9}, 32), cryptox.ValueContext{AccountID: "account-chain", AccountGeneration: "1", EnvironmentID: "env-fixture", KeyVersion: "1", Name: mutation.Name}, []byte("synthetic-B"))
	check(t, err)
	mutation.Payload = cryptox.EncodeBase64(payload)
	signed, err := cryptox.SignMutation(mutation, b)
	check(t, err)
	var bgrant cryptox.SignedGrantWire
	for _, a := range f.Approval.IssuerProof.Authorities {
		if a.Grant.Grant.SubjectDeviceID == "device-B" {
			bgrant = a.Grant
		}
	}
	auth := SignedGrant{Grant: bgrant.Grant, Signature: bgrant.Signature}
	pull.Events = append(pull.Events, Event{Sequence: 2, Mutation: SignedMutation{Mutation: signed.Mutation, Signature: signed.Signature}, Authorization: &auth})
	pull.Sequence = 2
	state, err := v.VerifyPull(context.Background(), pull, localstate.CloudSnapshot{})
	check(t, err)
	if state.Environments["env-fixture"].Values["FIXTURE_KEY"] != "synthetic-only" || state.Environments["env-fixture"].Values["B_VALUE"] != "synthetic-B" {
		t.Fatal("ancestor history not decrypted")
	}
	for _, field := range []string{"unknown-env", "unknown-key-version", "new-issuer", "account-generation"} {
		t.Run(field, func(t *testing.T) {
			p := issuerClientPull(f)
			g := p.Grants[0].Grant
			switch field {
			case "unknown-env":
				g.EnvironmentID = "unproven-env"
			case "unknown-key-version":
				g.KeyVersion = "2"
			case "new-issuer":
				g.IssuerDeviceID = "directory-only-device"
			case "account-generation":
				g.AccountGeneration = "2"
			}
			sg, err := cryptox.SignGrant(g, b)
			check(t, err)
			p.Grants[0] = SignedGrant{Grant: sg.Grant, Signature: sg.Signature}
			if _, err = v.VerifyPull(context.Background(), p, localstate.CloudSnapshot{}); err == nil {
				t.Fatal("proof scope expanded")
			}
		})
	}
	// 已有历史签名来源不产生当前权限：当前过期/撤销授权必须停止本地环境。
	expired := issuerClientTrust(t, f)
	expired.Now = func() time.Time { return time.Unix(2030000301, 0) }
	ev, err := NewPinnedVerifierV2(expired)
	check(t, err)
	defer ev.Close()
	expiredPull := issuerClientPull(f)
	expiredPull.Events = nil
	st, err := ev.VerifyPull(context.Background(), expiredPull, localstate.CloudSnapshot{})
	check(t, err)
	if len(st.Environments) != 0 {
		t.Fatal("historical authority reactivated expired current grant")
	}
	revoke := f.Approval.Grants[0].Grant
	revoke.Role = "none"
	revoke.Envelope = ""
	revoke.ExpiresAt = "0"
	revoke.GrantGeneration = "2"
	revoke.IdempotencyKey = "C-revoke"
	sg, err := cryptox.SignGrant(revoke, b)
	check(t, err)
	p := issuerClientPull(f)
	p.Grants = []SignedGrant{{Grant: sg.Grant, Signature: sg.Signature}}
	p.Sequence = 3
	p.Events = nil
	st, err = v.VerifyPull(context.Background(), p, state)
	check(t, err)
	if len(st.Environments) != 0 {
		t.Fatal("proof reactivated revoked grant")
	}
}
func TestIssuerReceiptNeedsExactLocalDualKeysAndStrictV2(t *testing.T) {
	f := issuerClientVector(t)
	trust := issuerClientTrust(t, f)
	for _, field := range []string{"account", "generation", "device", "signing", "receiving", "initiator-signature", "proof", "version"} {
		t.Run(field, func(t *testing.T) {
			x := issuerClientTrust(t, issuerClientVector(t))
			switch field {
			case "account":
				x.AccountID = "directory-only-account"
			case "generation":
				x.AccountGeneration = 2
			case "device":
				x.DeviceID = "directory-only-device"
			case "signing":
				x.DeviceSigningPublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32)).Public().(ed25519.PublicKey)
			case "receiving":
				x.ReceivingPrivateKey = bytes.Repeat([]byte{14}, 32)
			case "initiator-signature":
				x.Receipt.Approval.InitiatorSignature = ""
			case "proof":
				x.Receipt.Approval.IssuerProof.Path = nil
			case "version":
				x.Receipt.Approval.CertificateVersion = "1"
			}
			if v, err := NewPinnedVerifierV2(x); err == nil {
				v.Close()
				t.Fatal("unbound local trust accepted")
			}
		})
	}
	data, err := json.Marshal(trust.Receipt)
	check(t, err)
	if _, err = DecodeEnrollmentReceiptV2(data); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(append([]byte(nil), data...), []byte(" {}")...), []byte(strings.Replace(string(data), `"certificateVersion":"2"`, `"certificateVersion":"1"`, 1)), []byte(strings.Replace(string(data), `"idempotencyKey":"pair-C"`, `"idempotencyKey":"pair-C","managers":{}`, 1)), bytes.Repeat([]byte{' '}, cryptox.MaxIssuerProofBytes+513)} {
		if _, err = DecodeEnrollmentReceiptV2(bad); err == nil {
			t.Fatal("invalid receipt JSON accepted")
		}
	}
	// v1 decoder 不允许吸收 v2 proof 字段。
	var old EnrollmentReceipt
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&old) == nil {
		t.Fatal("v2 downgraded to legacy receipt")
	}
}
func TestIssuerResumeQueriesExactCompletedV2WithoutRestoringPAKE(t *testing.T) {
	f := issuerClientVector(t)
	receipt := EnrollmentReceiptV2{IdempotencyKey: "pair-C", Approval: f.Approval}
	seq := uint64(4)
	status := PairingStatusV2{State: "complete", IdempotencyKey: receipt.IdempotencyKey, CertificateVersion: "2", Capabilities: []string{cryptox.IssuerProofCapability}, PairingProfile: pairing.Profile, Context: pairing.Context(f.Approval.Context), Approval: &f.Approval, Sequence: &seq}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/pairings-v2/pair-C") {
			t.Error("resumed through wrong route")
		}
		_ = json.NewEncoder(w).Encode(status)
	}))
	defer server.Close()
	cfg := EnrollmentConfig{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: "account-chain", AccountGeneration: 1, DeviceID: "device-C", LoginToken: cryptox.EncodeBase64(make([]byte, 32)), SigningKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)), ReceivingPrivateKey: bytes.Repeat([]byte{13}, 32), Engine: testEngine(t), Now: func() time.Time { return time.Unix(2030000400, 0) }}
	e, err := ResumeEnrollmentV2(cfg, receipt)
	check(t, err)
	defer e.Close()
	result, err := e.Complete(context.Background())
	check(t, err)
	result.Verifier.Close()
	if calls != 1 || result.Sequence != seq || e.session != nil {
		t.Fatal("resume restored ephemeral state or rewrote completion")
	}
	for _, field := range []string{"missing-version", "missing-capability", "downgrade", "unknown-capability", "changed-proof"} {
		t.Run(field, func(t *testing.T) {
			before := status
			switch field {
			case "missing-version":
				status.CertificateVersion = ""
			case "missing-capability":
				status.Capabilities = nil
			case "downgrade":
				status.CertificateVersion = "1"
			case "unknown-capability":
				status.Capabilities = []string{"directory-tofu"}
			case "changed-proof":
				a := f.Approval
				a.IssuerProof.Targets = nil
				status.Approval = &a
			}
			if _, err = e.Complete(context.Background()); err == nil {
				t.Fatal("completion accepted downgrade/mutated proof")
			}
			status = before
		})
	}
}
func TestIssuerDefaultEnrollmentV2FailsBeforeNetwork(t *testing.T) {
	f := issuerClientVector(t)
	cfg := EnrollmentConfig{Endpoint: "https://synthetic.invalid", AccountID: "account-chain", AccountGeneration: 1, DeviceID: "device-C", LoginToken: cryptox.EncodeBase64(make([]byte, 32)), SigningKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)), ReceivingPrivateKey: bytes.Repeat([]byte{13}, 32), Engine: testEngine(t)}
	e, err := NewEnrollmentV2(cfg)
	check(t, err)
	defer e.Close()
	if !pairing.NativeAvailable() {
		if _, err = e.Begin(context.Background(), "device-B", "pair-C", []byte("12345678")); !errors.Is(err, pairing.ErrUnavailable) {
			t.Fatal(err)
		}
	}
	f.Approval.InitiatorSignature = ""
	if _, err = ResumeEnrollmentV2(cfg, EnrollmentReceiptV2{IdempotencyKey: "pair-C", Approval: f.Approval}); err == nil {
		t.Fatal("unsigned pending receipt resumed")
	}
	e.Close()
	if _, err = e.Complete(context.Background()); !errors.Is(err, pairing.ErrState) {
		t.Fatal("closed v2 enrollment did not fail closed", err)
	}
	if _, err = e.Receipt(); !errors.Is(err, pairing.ErrState) {
		t.Fatal("closed v2 enrollment exposed receipt", err)
	}

}
