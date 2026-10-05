package syncclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/internal/dagfixture"
	"github.com/harmonia-vault/core-go/localstate"
)

var fixedNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type cryptoFixture struct {
	verifier                         *PinnedVerifier
	managerPrivate, devicePrivate    ed25519.PrivateKey
	devicePublic                     ed25519.PublicKey
	environmentKey, receivingPrivate []byte
	grant                            SignedGrant
	proof                            cryptox.IssuerRecoveryDAG
}

func newCryptoFixture(t *testing.T) *cryptoFixture {
	t.Helper()
	managerPublic, managerPrivate, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	devicePublic, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	receivingPublic, receivingPrivate, err := cryptox.GenerateReceivingKey()
	check(t, err)
	key, err := cryptox.GenerateEnvironmentKey()
	check(t, err)
	grant := cryptox.Grant{AccountID: "acct", AccountGeneration: "1", IssuerDeviceID: "manager", SubjectDeviceID: "dev", SubjectSigningPublicKey: cryptox.EncodeBase64(devicePublic), SubjectReceivingPublicKey: cryptox.EncodeBase64(receivingPublic), EnvironmentID: "env", KeyVersion: "1", GrantGeneration: "1", Role: "rw", ExpiresAt: "0", IdempotencyKey: "grant-1"}
	envelope, err := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: "acct", AccountGeneration: "1", EnvironmentID: "env", KeyVersion: "1", RecipientType: "device", RecipientID: "dev", RecipientGeneration: "1", RecipientPublicKey: grant.SubjectReceivingPublicKey})
	check(t, err)
	grant.Envelope = cryptox.EncodeBase64(envelope)
	signed, err := cryptox.SignGrant(grant, managerPrivate)
	check(t, err)
	_, recovery, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	managerX, _, err := cryptox.GenerateReceivingKey()
	check(t, err)
	recX, _, err := cryptox.GenerateReceivingKey()
	check(t, err)
	root, err := cryptox.SignTrustRoot("acct", "1", cryptox.TrustRoot{RootDeviceID: "manager", RootSigningPublicKey: cryptox.EncodeBase64(managerPublic), RootReceivingPublicKey: cryptox.EncodeBase64(managerX), RecoveryGeneration: "1", RecoverySigningPublicKey: cryptox.EncodeBase64(recovery.Public().(ed25519.PublicKey)), RecoveryReceivingPublicKey: cryptox.EncodeBase64(recX)}, recovery)
	check(t, err)
	rootGrant := grant
	rootGrant.SubjectDeviceID = "manager"
	rootGrant.SubjectSigningPublicKey = root.RootSigningPublicKey
	rootGrant.SubjectReceivingPublicKey = root.RootReceivingPublicKey
	rootGrant.Role = "admin"
	rootGrant.IdempotencyKey = "init-root"
	rootEnvelope, err := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{"acct", "1", "env", "1", "device", "manager", "1", root.RootReceivingPublicKey})
	check(t, err)
	rootGrant.Envelope = cryptox.EncodeBase64(rootEnvelope)
	rootSigned, err := cryptox.SignGrant(rootGrant, managerPrivate)
	check(t, err)
	recEnvelope, err := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{"acct", "1", "env", "1", "recovery", "acct", "1", root.RecoveryReceivingPublicKey})
	check(t, err)
	p := dagfixture.Root(t, "acct", root, managerPrivate, recovery, []cryptox.InitializationEnvironment{{EnvironmentID: "env", KeyVersion: "1", RecoveryEnvelope: cryptox.EncodeBase64(recEnvelope), Grant: cryptox.GrantToWire(rootSigned)}})
	context := cryptox.EnrollmentContext{AccountID: "acct", AccountGeneration: "1", Purpose: "enroll-device", SessionID: "pair-fixture", ChallengeNonce: cryptox.EncodeBase64(make([]byte, 32)), ExpiresAt: "4102444800", ApproverDeviceID: "manager", ApproverSigningPublicKey: root.RootSigningPublicKey, ApproverReceivingPublicKey: root.RootReceivingPublicKey, InitiatorDeviceID: "dev", InitiatorSigningPublicKey: grant.SubjectSigningPublicKey, InitiatorReceivingPublicKey: grant.SubjectReceivingPublicKey}
	approval, p := dagfixture.Enroll(t, p, context, []cryptox.SignedGrantWire{cryptox.GrantToWire(signed)}, managerPrivate, devicePrivate)
	verifier, err := NewPinnedVerifierV5(IssuerDAGPinnedTrust{AccountID: "acct", AccountGeneration: 1, DeviceID: "dev", DeviceSigningPublicKey: devicePublic, ReceivingPrivateKey: receivingPrivate, Receipt: EnrollmentReceiptV5{IdempotencyKey: "pair-fixture", Approval: approval}, Now: func() time.Time { return fixedNow }})
	check(t, err)
	return &cryptoFixture{verifier: verifier, managerPrivate: managerPrivate, devicePrivate: devicePrivate, devicePublic: devicePublic, environmentKey: key, receivingPrivate: receivingPrivate, grant: SignedGrant{Grant: signed.Grant, Signature: signed.Signature}, proof: p}

}
func (f *cryptoFixture) resignGrant(t *testing.T, g Grant) SignedGrant {
	t.Helper()
	signed, err := cryptox.SignGrant(g, f.managerPrivate)
	check(t, err)
	return SignedGrant{Grant: signed.Grant, Signature: signed.Signature}
}
func (f *cryptoFixture) event(t *testing.T, sequence uint64, value string) Event {
	t.Helper()
	packet, err := cryptox.EncryptValue(f.environmentKey, cryptox.ValueContext{AccountID: "acct", AccountGeneration: "1", EnvironmentID: "env", KeyVersion: "1", Name: "TOKEN"}, []byte(value))
	check(t, err)
	m := cryptox.Mutation{AccountID: "acct", AccountGeneration: "1", DeviceID: "dev", EnvironmentID: "env", KeyVersion: "1", GrantGeneration: "1", Operation: "put", IdempotencyKey: fmt.Sprintf("write-%d", sequence), Name: "TOKEN", Payload: cryptox.EncodeBase64(packet)}
	signed, err := cryptox.SignMutation(m, f.devicePrivate)
	check(t, err)
	authorization := f.grant
	return Event{Sequence: sequence, Mutation: SignedMutation{Mutation: signed.Mutation, Signature: signed.Signature}, Authorization: &authorization}
}
func (f *cryptoFixture) pull(sequence uint64, events ...Event) Pull {
	p := cloneDAGEvidence(f.proof)
	return Pull{IssuerDAGEvidence: &p, Full: true, AccountID: "acct", AccountGeneration: "1", Sequence: sequence, Grants: []SignedGrant{f.grant}, Events: events}
}
func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func TestPinnedVerifierRealHPKESignatureAndAEAD(t *testing.T) {
	f := newCryptoFixture(t)
	snapshot, err := f.verifier.VerifyPull(context.Background(), f.pull(2, f.event(t, 1, "first"), f.event(t, 2, "last")), localstate.CloudSnapshot{})
	check(t, err)
	if snapshot.Environments["env"].Values["TOKEN"] != "last" || snapshot.SeenMutations["dev/write-1"].Sequence != 1 {
		t.Fatal(snapshot)
	}
	incremental := f.pull(3, f.event(t, 3, "incremental"))
	incremental.Full = false
	next, err := f.verifier.VerifyPull(context.Background(), incremental, snapshot)
	check(t, err)
	if next.Environments["env"].Values["TOKEN"] != "incremental" {
		t.Fatal(next)
	}
}
func TestPinnedVerifierRejectsUnpinnedIssuerAndExactKeyMismatch(t *testing.T) {
	for _, kind := range []string{"issuer", "signing-key", "receiving-key", "generation"} {
		t.Run(kind, func(t *testing.T) {
			f := newCryptoFixture(t)
			grant := f.grant.Grant
			switch kind {
			case "issuer":
				grant.IssuerDeviceID = "stranger"
			case "signing-key":
				grant.SubjectSigningPublicKey = cryptox.EncodeBase64(make([]byte, 32))
			case "receiving-key":
				grant.SubjectReceivingPublicKey = cryptox.EncodeBase64(make([]byte, 32))
			case "generation":
				grant.AccountGeneration = "2"
			}
			pull := f.pull(1)
			pull.Grants = []SignedGrant{f.resignGrant(t, grant)}
			if _, err := f.verifier.VerifyPull(context.Background(), pull, localstate.CloudSnapshot{}); err == nil {
				t.Fatal("untrusted grant accepted")
			}
		})
	}
}
func TestPinnedVerifierRejectsROCiphertextForge(t *testing.T) {
	f := newCryptoFixture(t)
	event := f.event(t, 1, "forged-by-key-holder")
	grant := f.grant.Grant
	grant.Role = "ro"
	authorization := f.resignGrant(t, grant)
	event.Authorization = &authorization
	if _, err := f.verifier.VerifyPull(context.Background(), f.pull(1, event), localstate.CloudSnapshot{}); err == nil {
		t.Fatal("RO ciphertext forge accepted")
	}
}
func TestPinnedVerifierRejectsSignedAEADTampering(t *testing.T) {
	f := newCryptoFixture(t)
	event := f.event(t, 1, "synthetic")
	packet, err := cryptox.DecodeBase64(event.Mutation.Mutation.Payload, 40, cryptox.MaxValueBytes+40)
	check(t, err)
	packet[len(packet)-1] ^= 1
	event.Mutation.Mutation.Payload = cryptox.EncodeBase64(packet)
	signed, err := cryptox.SignMutation(event.Mutation.Mutation, f.devicePrivate)
	check(t, err)
	event.Mutation.Signature = signed.Signature
	if _, err = f.verifier.VerifyPull(context.Background(), f.pull(1, event), localstate.CloudSnapshot{}); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
func TestFullHistoryCannotReassignSeenSequence(t *testing.T) {
	f := newCryptoFixture(t)
	a := f.event(t, 1, "A")
	b := f.event(t, 2, "B")
	previous, err := f.verifier.VerifyPull(context.Background(), f.pull(2, a, b), localstate.CloudSnapshot{})
	check(t, err)
	b.Sequence = 1
	a.Sequence = 2
	if _, err = f.verifier.VerifyPull(context.Background(), f.pull(3, b, a), previous); err == nil {
		t.Fatal("full history reordered old signed writes")
	}
}
func TestFullHistoryRejectsDuplicateIDAndFreshSequenceReplay(t *testing.T) {
	f := newCryptoFixture(t)
	event := f.event(t, 1, "A")
	duplicate := event
	duplicate.Sequence = 2
	if _, err := f.verifier.VerifyPull(context.Background(), f.pull(2, event, duplicate), localstate.CloudSnapshot{}); err == nil {
		t.Fatal("duplicate event ID accepted")
	}
	previous, err := f.verifier.VerifyPull(context.Background(), f.pull(1, event), localstate.CloudSnapshot{})
	check(t, err)
	duplicate.Sequence = 2
	pull := f.pull(2, duplicate)
	pull.Full = false
	if _, err = f.verifier.VerifyPull(context.Background(), pull, previous); err == nil {
		t.Fatal("old signed mutation replayed at fresh sequence")
	}
}
func TestUnchangedFullHistoryAndNewWritesRemainValid(t *testing.T) {
	f := newCryptoFixture(t)
	a := f.event(t, 1, "A")
	previous, err := f.verifier.VerifyPull(context.Background(), f.pull(1, a), localstate.CloudSnapshot{})
	check(t, err)
	next, err := f.verifier.VerifyPull(context.Background(), f.pull(2, a, f.event(t, 2, "B")), previous)
	check(t, err)
	if next.Environments["env"].Values["TOKEN"] != "B" {
		t.Fatal(next)
	}
}
func TestGrantRevocationCheckpointSurvivesCacheRemoval(t *testing.T) {
	f := newCryptoFixture(t)
	previous, err := f.verifier.VerifyPull(context.Background(), f.pull(1, f.event(t, 1, "A")), localstate.CloudSnapshot{})
	check(t, err)
	g := f.grant.Grant
	g.Role = "none"
	g.GrantGeneration = "2"
	g.Envelope = ""
	g.IdempotencyKey = "revoke-2"
	revoked := f.pull(2)
	revoked.Full = false
	revoked.Grants = []SignedGrant{f.resignGrant(t, g)}
	next, err := f.verifier.VerifyPull(context.Background(), revoked, previous)
	check(t, err)
	if len(next.Environments) != 0 || next.GrantCheckpoints["env"] != 2 {
		t.Fatal(next)
	}
	replayed := f.pull(3)
	if _, err = f.verifier.VerifyPull(context.Background(), replayed, next); err == nil {
		t.Fatal("old writable grant revived after revoke")
	}
}
func TestNewAuthorizationRequiresAndAcceptsFullCatchup(t *testing.T) {
	f := newCryptoFixture(t)
	previous := localstate.CloudSnapshot{IssuerEvidence: fixtureDAGBytes(t, f.proof), AccountID: "acct", AccountGeneration: 1, Sequence: 10, Environments: map[string]localstate.Environment{}}
	incremental := f.pull(11)
	incremental.Full = false
	if _, err := f.verifier.VerifyPull(context.Background(), incremental, previous); !errors.Is(err, ErrFullPullRequired) {
		t.Fatal(err)
	}
	full := f.pull(11, f.event(t, 1, "historical-before-grant"))
	next, err := f.verifier.VerifyPull(context.Background(), full, previous)
	check(t, err)
	if next.Environments["env"].Values["TOKEN"] != "historical-before-grant" {
		t.Fatal(next)
	}
}
func TestMutationMustCarryWriterAuthorization(t *testing.T) {
	f := newCryptoFixture(t)
	event := f.event(t, 1, "A")
	event.Authorization = nil
	if _, err := f.verifier.VerifyPull(context.Background(), f.pull(1, event), localstate.CloudSnapshot{}); err == nil {
		t.Fatal("unsigned write authorization accepted")
	}
}

func fixtureDAGBytes(t *testing.T, p cryptox.IssuerRecoveryDAG) []byte {
	t.Helper()
	b, e := json.Marshal(p)
	check(t, e)
	return b
}
