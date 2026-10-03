package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

type recoverySourceFixture struct {
	Recovery struct {
		Now        int64                              `json:"syntheticNow"`
		Seeds      map[string]string                  `json:"syntheticSeedsHex"`
		Pin        cryptox.PinnedIssuerRoot           `json:"rootPin"`
		Original   cryptox.OriginalInitialization     `json:"originalInitialization"`
		Transition cryptox.AcceptedRecoveryTransition `json:"oldRecoveryTransition"`
		Accepted   cryptox.AcceptedRecoveredDevice    `json:"recoveredDevice"`
	} `json:"recovery"`
	Proof     cryptox.IssuerRecoveryProof `json:"proof"`
	ChildSeed string                      `json:"syntheticChildEdSeedHex"`
}

func recoverySource(t *testing.T) recoverySourceFixture {
	t.Helper()
	b, e := os.ReadFile("../cryptox/testdata/issuer-recovery-v1.json")
	check(t, e)
	var f recoverySourceFixture
	check(t, json.Unmarshal(b, &f))
	return f
}
func recoveryTestHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	check(t, e)
	return b
}
func recoveryTrust(t *testing.T, f recoverySourceFixture) RecoveredDevicePinnedTrust {
	t.Helper()
	r := f.Recovery
	key := ed25519.NewKeyFromSeed(recoveryTestHex(t, r.Seeds["deviceEd"]))
	defer clear(key)
	p, e := cryptox.BuildRecoveredDeviceIssuerEvidence(r.Pin, r.Original, []cryptox.AcceptedRecoveryTransition{r.Transition}, r.Accepted)
	check(t, e)
	return RecoveredDevicePinnedTrust{Trust: PinnedTrust{AccountID: r.Pin.AccountID, AccountGeneration: 1, DeviceID: r.Accepted.Submission.Enrollment.DeviceID, DeviceSigningPublicKey: key.Public().(ed25519.PublicKey), ReceivingPrivateKey: recoveryTestHex(t, r.Seeds["deviceX"]), Now: func() time.Time { return time.Unix(r.Now, 0) }}, Pin: r.Pin, Evidence: p, Accepted: r.Accepted}
}
func TestRecoveredDevicePinnedSourceTypedBindingAndDataLedger(t *testing.T) {
	f := recoverySource(t)
	tr := recoveryTrust(t, f)
	v, e := NewRecoveredDevicePinnedVerifier(tr)
	check(t, e)
	defer v.Close()
	own := tr.Accepted.Submission.Grants[0]
	g := own.Grant
	key := ed25519.NewKeyFromSeed(recoveryTestHex(t, f.Recovery.Seeds["deviceEd"]))
	defer clear(key)
	envKey, e := cryptox.UnwrapEnvironmentKey(tr.Trust.ReceivingPrivateKey, cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey}, mustRaw(t, g.Envelope))
	check(t, e)
	defer clear(envKey)
	name := "SYNTHETIC_RECOVERED_VALUE"
	payload, e := cryptox.EncryptValue(envKey, cryptox.ValueContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, Name: name}, []byte("synthetic-recovered-data"))
	check(t, e)
	signed, e := cryptox.SignMutation(cryptox.Mutation{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, DeviceID: g.SubjectDeviceID, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, GrantGeneration: g.GrantGeneration, Operation: "put", IdempotencyKey: "recovered-synthetic-write", Name: name, Payload: cryptox.EncodeBase64(payload)}, key)
	check(t, e)
	p := tr.Evidence
	pull := Pull{Full: true, AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, Sequence: 32, Grants: []SignedGrant{{Grant: g, Signature: own.Signature}}, Events: []Event{{Sequence: 32, Mutation: SignedMutation{Mutation: signed.Mutation, Signature: signed.Signature}, Authorization: &SignedGrant{Grant: g, Signature: own.Signature}}}, IssuerRecoveryEvidence: &p}
	early := pull
	early.Sequence = tr.Accepted.Sequence - 1
	early.Events = nil
	if _, e = v.VerifyPull(context.Background(), early, localstate.CloudSnapshot{}); e == nil {
		t.Fatal("recovery graph accepted ahead of account durable checkpoint")
	}
	cloud, e := v.VerifyPull(context.Background(), pull, localstate.CloudSnapshot{})
	check(t, e)
	if cloud.Environments[g.EnvironmentID].Values[name] != "synthetic-recovered-data" || cloud.Environments[g.EnvironmentID].Source == nil || len(cloud.IssuerEvidence) == 0 {
		t.Fatal("verified recovered data/source/ledger not recorded")
	}
	restarted, e := NewRecoveredDevicePinnedVerifier(tr)
	check(t, e)
	defer restarted.Close()
	check(t, restarted.ValidateStoredIssuerEvidence(cloud))
	earlier := cloud
	earlier.Sequence = tr.Accepted.Sequence - 1
	earlier.AuthorizationSequence = earlier.Sequence
	if restarted.ValidateStoredIssuerEvidence(earlier) == nil {
		t.Fatal("protected recovery ledger ahead of stored account checkpoint")
	}

	missing := cloud
	missing.IssuerEvidence = nil
	if restarted.ValidateStoredIssuerEvidence(missing) == nil {
		t.Fatal("cert4 cache accepted without sealed source ledger")
	}
	rollback := cloud
	rollback.IssuerEvidence = []byte(`{"profile":"harmonia/issuer-proof/v2"}`)
	if restarted.ValidateStoredIssuerEvidence(rollback) == nil {
		t.Fatal("old profile fallback accepted")
	}
	// candidate 不能用已经受保护的已见签值/授权取代丢失的来源或初始化。
	bad := cloneRecoveryEvidence(p)
	bad.Transitions = []cryptox.AcceptedRecoveryTransition{}
	pull.IssuerRecoveryEvidence = &bad
	if _, e = v.VerifyPull(context.Background(), pull, cloud); e == nil {
		t.Fatal("seen recovery head rolled back")
	}
	pull.IssuerRecoveryEvidence = nil
	pull.IssuerEvidence = &cryptox.IssuerProofV2{}
	if _, e = v.VerifyPull(context.Background(), pull, cloud); e == nil {
		t.Fatal("old capability proof silently accepted")
	}
}
func mustRaw(t *testing.T, s string) []byte {
	t.Helper()
	b, e := cryptox.DecodeBase64(s, 1, 1<<20)
	check(t, e)
	return b
}
func TestRecoveredDevicePinnedContextRejectsWrongIdentityAndReceipt(t *testing.T) {
	f := recoverySource(t)
	for _, kind := range []string{"manager-list", "new-root", "own-ed", "own-x", "accepted-sequence", "missing-accepted"} {
		t.Run(kind, func(t *testing.T) {
			tr := recoveryTrust(t, f)
			switch kind {
			case "manager-list":
				tr.Trust.Managers = map[string]ed25519.PublicKey{"directory-device": make([]byte, 32)}
			case "new-root":
				tr.Pin.DeviceID = "new-root"
			case "own-ed":
				tr.Trust.DeviceSigningPublicKey = make([]byte, 32)
			case "own-x":
				tr.Trust.ReceivingPrivateKey = bytes.Repeat([]byte{66}, 32)
			case "accepted-sequence":
				tr.Accepted.Sequence++
			case "missing-accepted":
				tr.Evidence.RecoveredDevices = []cryptox.AcceptedRecoveredDevice{}
			}
			if v, e := NewRecoveredDevicePinnedVerifier(tr); e == nil {
				v.Close()
				t.Fatal("untrusted replacement accepted")
			}
		})
	}
}
func TestCert4OriginalReceiptAndClosedEnrollmentBoundary(t *testing.T) {
	f := recoverySource(t)
	p := cloneRecoveryEvidence(f.Proof)
	last := p.Path[len(p.Path)-1].Enrollment
	a := last.Approval
	p.Path = p.Path[:len(p.Path)-1]
	p.Targets = []cryptox.IssuerTarget{}
	filtered := []cryptox.IssuerRecoveryAuthority{}
	for _, n := range p.Authorities {
		if n.Grant.Grant.SubjectDeviceID != a.Context.InitiatorDeviceID {
			filtered = append(filtered, n)
		}
	}
	p.Authorities = filtered
	for _, g := range f.Recovery.Accepted.Submission.Grants {
		h, e := cryptox.IssuerAuthorityHash(g)
		check(t, e)
		p.Targets = append(p.Targets, cryptox.IssuerTarget{EnvironmentID: g.Grant.EnvironmentID, AuthorityHash: h})
	}
	approval := cryptox.EnrollmentApprovalV4{CertificateVersion: "4", Capabilities: []string{cryptox.RecoveryAuthorityCapability}, Context: a.Context, PairingProfile: a.PairingProfile, TranscriptHash: a.TranscriptHash, Grants: a.Grants, IssuerProof: p, ApproverSignature: a.ApproverSignature, InitiatorSignature: a.InitiatorSignature}
	receipt := EnrollmentReceiptV4{IdempotencyKey: "protected-cert4-original", Approval: approval}
	data, e := json.Marshal(receipt)
	check(t, e)
	r, e := DecodeEnrollmentReceiptV4(data)
	check(t, e)
	key := ed25519.NewKeyFromSeed(recoveryTestHex(t, f.ChildSeed))
	defer clear(key)
	tr := IssuerRecoveryPinnedTrust{AccountID: a.Context.AccountID, AccountGeneration: 1, DeviceID: a.Context.InitiatorDeviceID, DeviceSigningPublicKey: key.Public().(ed25519.PublicKey), ReceivingPrivateKey: bytes.Repeat([]byte{17}, 32), Receipt: r, Now: func() time.Time { return time.Unix(f.Recovery.Now, 0) }}
	v, e := NewPinnedVerifierV4(tr)
	check(t, e)
	defer v.Close()
	if v.evidenceRoot.DeviceID != f.Recovery.Pin.DeviceID || len(v.trust.Managers) != 0 {
		t.Fatal("cert4 moved original pin or created global managers")
	}
	own := r.Approval.Grants[0]
	full := cloneRecoveryEvidence(f.Proof)
	childCloud, e := v.VerifyPull(context.Background(), Pull{Full: true, AccountID: tr.AccountID, AccountGeneration: "1", Sequence: 32, Grants: []SignedGrant{{Grant: own.Grant, Signature: own.Signature}}, IssuerRecoveryEvidence: &full}, localstate.CloudSnapshot{})
	check(t, e)
	if childCloud.Environments[own.Grant.EnvironmentID].Role != localstate.ReadOnly {
		t.Fatal("cert4 RO child escalated")
	}
	check(t, v.ValidateStoredIssuerEvidence(childCloud))
	forged := childCloud
	forged.Environments = copyMap(childCloud.Environments)
	env := forged.Environments[own.Grant.EnvironmentID]
	env.Role = localstate.Admin
	forged.Environments[env.ID] = env
	if v.ValidateStoredIssuerEvidence(forged) == nil {
		t.Fatal("cert4 sealed RO cache forged Admin")
	}

	for _, kind := range []string{"old-cap", "old-domain", "tampered-recovery"} {
		t.Run(kind, func(t *testing.T) {
			bad := tr
			bad.Receipt = cloneReceiptV4(tr.Receipt)
			switch kind {
			case "old-cap":
				bad.Receipt.Approval.Capabilities = []string{cryptox.EnvironmentOriginCapability}
			case "old-domain":
				bad.Receipt.Approval.CertificateVersion = "3"
			case "tampered-recovery":
				bad.Receipt.Approval.IssuerProof.RecoveredDevices[0].Sequence++
			}
			if other, e := NewPinnedVerifierV4(bad); e == nil {
				other.Close()
				t.Fatal("cert4 original receipt allowed downgrade/substitution")
			}
		})
	}
	engine, e := localstate.New(&volatileStore{state: localstate.EmptyState()})
	check(t, e)
	enrollment, e := NewEnrollmentV4(EnrollmentConfig{Endpoint: "https://synthetic.example.invalid", AccountID: a.Context.AccountID, AccountGeneration: 1, DeviceID: a.Context.InitiatorDeviceID, LoginToken: cryptox.EncodeBase64(bytes.Repeat([]byte{88}, 32)), SigningKey: key, ReceivingPrivateKey: tr.ReceivingPrivateKey, Engine: engine})
	check(t, e)
	enrollment.Close()
	if _, e = enrollment.Complete(context.Background()); e == nil {
		t.Fatal("closed cert4 enrollment completed")
	}
}
