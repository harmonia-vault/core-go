package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

func recoveryStateFixture(t *testing.T) (Config, protectedState) {
	t.Helper()
	config := testConfig(t)
	now := int64(1900000000)
	config.Now = func() time.Time { return time.Unix(now, 0) }
	w := selfMust(New(config))
	defer w.Close()
	state := clone(w.state)
	state.AccountID = "recovery-unit-account"
	state.AccountGeneration = "1"
	_, rootKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	rootID := "old-root"
	_, rootReceive, e := cryptox.GenerateReceivingKey()
	if e != nil {
		t.Fatal(e)
	}
	rootX := selfMust(ecdh.X25519().NewPrivateKey(rootReceive))
	seed := bytes.Repeat([]byte{17}, 32)
	recover := selfMust(cryptox.DeriveRecoveryKeys(seed, state.AccountID, "1", "1"))
	defer clear(recover.SigningPrivate)
	defer clear(recover.ReceivingPrivate)
	root := selfMust(cryptox.SignTrustRoot(state.AccountID, "1", cryptox.TrustRoot{RootDeviceID: rootID, RootSigningPublicKey: cryptox.EncodeBase64(rootKey.Public().(ed25519.PublicKey)), RootReceivingPublicKey: cryptox.EncodeBase64(rootX.PublicKey().Bytes()), RecoveryGeneration: "1", RecoverySigningPublicKey: cryptox.EncodeBase64(recover.SigningPublic), RecoveryReceivingPublicKey: cryptox.EncodeBase64(recover.ReceivingPublic)}, recover.SigningPrivate))
	key := selfMust(cryptox.GenerateEnvironmentKey())
	defer clear(key)
	envEnvelope := selfMust(cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: state.AccountID, AccountGeneration: "1", EnvironmentID: "env", KeyVersion: "1", RecipientType: "recovery", RecipientID: state.AccountID, RecipientGeneration: "1", RecipientPublicKey: root.RecoveryReceivingPublicKey}))
	devEnvelope := selfMust(cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: state.AccountID, AccountGeneration: "1", EnvironmentID: "env", KeyVersion: "1", RecipientType: "device", RecipientID: rootID, RecipientGeneration: "1", RecipientPublicKey: root.RootReceivingPublicKey}))
	grant := selfMust(cryptox.SignGrant(cryptox.Grant{AccountID: state.AccountID, AccountGeneration: "1", IssuerDeviceID: rootID, SubjectDeviceID: rootID, SubjectSigningPublicKey: root.RootSigningPublicKey, SubjectReceivingPublicKey: root.RootReceivingPublicKey, EnvironmentID: "env", KeyVersion: "1", GrantGeneration: "1", Role: "admin", ExpiresAt: "0", IdempotencyKey: "initial-unit", Envelope: cryptox.EncodeBase64(devEnvelope)}, rootKey))
	packet := selfMust(cryptox.EncryptValue(key, cryptox.ValueContext{AccountID: state.AccountID, AccountGeneration: "1", EnvironmentID: "env", KeyVersion: "1", Name: "RECOVERY_UNIT"}, []byte("synthetic-recovered-unit-value")))
	mutation := selfMust(cryptox.SignMutation(cryptox.Mutation{AccountID: state.AccountID, AccountGeneration: "1", DeviceID: rootID, EnvironmentID: "env", KeyVersion: "1", GrantGeneration: "1", Operation: "put", IdempotencyKey: "unit-recovered-write", Name: "RECOVERY_UNIT", Payload: cryptox.EncodeBase64(packet)}, rootKey))
	g := syncclient.SignedGrant{Grant: grant.Grant, Signature: grant.Signature}
	token := cryptox.EncodeBase64(bytes.Repeat([]byte{19}, 32))
	hash := sha256.Sum256([]byte(token))
	vault := recoveryVaultWire{AccountID: state.AccountID, AccountGeneration: "1", RecoveryGeneration: "1", RecoverySigningPublicKey: root.RecoverySigningPublicKey, RecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, RotationRequired: true, Sequence: 2, TrustRoot: &root, CurrentGrants: []syncclient.SignedGrant{g}, GrantHistory: []recoveryGrantEvent{{Sequence: 1, Grant: g}}, Environments: []cryptox.RecoveryEnvelope{{EnvironmentID: "env", KeyVersion: "1", Envelope: cryptox.EncodeBase64(envEnvelope)}}, Events: []syncclient.Event{{Sequence: 2, Mutation: syncclient.SignedMutation{Mutation: mutation.Mutation, Signature: mutation.Signature}, Authorization: &g}}}
	proposal := cryptox.InitializationProposal{IdempotencyKey: "initial-unit", Device: cryptox.InitializationDevice{ID: rootID, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey}, RecoveryGeneration: "1", RecoverySigningPublicKey: root.RecoverySigningPublicKey, RecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, TrustRootSignature: root.Signature, Environments: []cryptox.InitializationEnvironment{{EnvironmentID: "env", KeyVersion: "1", RecoveryEnvelope: cryptox.EncodeBase64(envEnvelope), Grant: cryptox.GrantToWire(grant)}}}
	proof := selfMust(cryptox.NewInitializationProof(state.AccountID, "1", "synthetic-original-login-token", "initial-unit-challenge", cryptox.EncodeBase64(bytes.Repeat([]byte{23}, 32)), strconv.FormatInt(now-1, 10), selfMust(proposal.Hash(state.AccountID, "1"))))
	vault.OriginalInitialization = &recoveryOriginalInitialization{Proposal: proposal, Proof: proof, DeviceSignature: selfMust(cryptox.SignInitializationProof(proof, rootKey)), RecoverySignature: selfMust(cryptox.SignInitializationProof(proof, recover.SigningPrivate)), Sequence: 1}
	state.Recovery = &recoveryRecord{Version: 1, AccountID: state.AccountID, AccountGeneration: "1", CreatedAt: now - 5, LastObservedAt: now, SessionToken: token, SessionHash: hex.EncodeToString(hash[:]), SessionExpiresAt: now + 895, RecoveryGeneration: "1", SigningPublicKey: root.RecoverySigningPublicKey, ReceivingPublicKey: root.RecoveryReceivingPublicKey, Root: root, Vault: vault, Keys: map[string]string{"env": cryptox.EncodeBase64(key)}}
	return config, state
}
func TestRecoveryProtectedBindingsRejectUnprovedAuthorityAndCiphertext(t *testing.T) {
	config, state := recoveryStateFixture(t)
	for _, tt := range []struct {
		name   string
		mutate func(*protectedState)
	}{
		{"candidate-issuer-evidence-duplicate-keys", func(s *protectedState) { s.Recovery.Vault.IssuerEvidence = json.RawMessage(`{"key":1,"key":2}`) }},
		{"candidate-issuer-evidence-too-large", func(s *protectedState) {
			s.Recovery.Vault.IssuerEvidence = json.RawMessage(`{"unused":"` + strings.Repeat("x", 1<<20) + `"}`)
		}},
		{"original-initialization-absent", func(s *protectedState) { s.Recovery.Vault.OriginalInitialization = nil }},
		{"original-proof-account", func(s *protectedState) { s.Recovery.Vault.OriginalInitialization.Proof.AccountID = "other" }},
		{"original-proof-generation", func(s *protectedState) { s.Recovery.Vault.OriginalInitialization.Proof.AccountGeneration = "2" }},
		{"original-proof-nonce", func(s *protectedState) {
			s.Recovery.Vault.OriginalInitialization.Proof.Nonce = cryptox.EncodeBase64(bytes.Repeat([]byte{55}, 32))
		}},
		{"original-proof-session-hash", func(s *protectedState) {
			s.Recovery.Vault.OriginalInitialization.Proof.LoginTokenHash = strings.Repeat("1", 64)
		}},
		{"original-device-signature", func(s *protectedState) {
			s.Recovery.Vault.OriginalInitialization.DeviceSignature = cryptox.EncodeBase64(make([]byte, 64))
		}},
		{"original-recovery-signature", func(s *protectedState) {
			s.Recovery.Vault.OriginalInitialization.RecoverySignature = cryptox.EncodeBase64(make([]byte, 64))
		}},
		{"original-proposal-grant-id", func(s *protectedState) {
			s.Recovery.Vault.OriginalInitialization.Proposal.Environments[0].Grant.Grant.IdempotencyKey = "later-signed-grant"
		}},
		{"original-proposal-recovery-public-key", func(s *protectedState) {
			s.Recovery.Vault.OriginalInitialization.Proposal.RecoverySigningPublicKey = cryptox.EncodeBase64(make([]byte, 32))
		}},
		{"original-proposal-root-device", func(s *protectedState) {
			s.Recovery.Vault.OriginalInitialization.Proposal.Device.ID = "substituted-root"
		}},
		{"account", func(s *protectedState) { s.Recovery.AccountID = "other" }},
		{"generation", func(s *protectedState) { s.Recovery.AccountGeneration = "2" }},
		{"session-token", func(s *protectedState) { s.Recovery.SessionToken = cryptox.EncodeBase64(bytes.Repeat([]byte{29}, 32)) }},
		{"root-signature", func(s *protectedState) { s.Recovery.Root.Signature = cryptox.EncodeBase64(make([]byte, 64)) }},
		{"missing-key", func(s *protectedState) { s.Recovery.Keys = map[string]string{} }},
		{"ciphertext", func(s *protectedState) {
			s.Recovery.Vault.Events[0].Mutation.Mutation.Payload = cryptox.EncodeBase64(make([]byte, 48))
		}},
		{"authorization-key-version", func(s *protectedState) { s.Recovery.Vault.Events[0].Authorization.Grant.KeyVersion = "2" }},
		{"unsigned-issuer", func(s *protectedState) { s.Recovery.Vault.Events[0].Authorization.Grant.IssuerDeviceID = "new-manager" }},
		{"replayed-event", func(s *protectedState) {
			s.Recovery.Vault.Events = append(s.Recovery.Vault.Events, s.Recovery.Vault.Events[0])
		}},
		{"unproved-trusted-root", func(s *protectedState) { s.Root = &s.Recovery.Root }},
		{"closed", func(s *protectedState) { s.Cloud.AccountClosed = true }},
		{"boolean-only-completion", func(s *protectedState) {
			s.Recovery.RotationCompleted = true
			s.Recovery.Vault.RotationRequired = false
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changed := clone(state)
			tt.mutate(&changed)
			c := config
			c.ProtectedState = selfMust(json.Marshal(changed))
			if w, err := New(c); err == nil {
				w.Close()
				t.Fatal("unproved/tampered recovery accepted")
			}
		})
	}
}
func TestRecoveryIsExplicitRestrictedViewNotCloudOrManagerAndLogoutScrubs(t *testing.T) {
	config, state := recoveryStateFixture(t)
	var saved []byte
	config.SaveProtectedState = func(b []byte) error { saved = bytes.Clone(b); return nil }
	config.ProtectedState = selfMust(json.Marshal(state))
	w := selfMust(New(config))
	defer w.Close()
	v := selfMust(w.RecoveryView())
	if v.Info.TrustedDevice || !v.Info.RotationRequired || len(v.Environments) != 1 || v.Environments[0].Variables["RECOVERY_UNIT"] != "synthetic-recovered-unit-value" {
		t.Fatal("verified restricted cache unavailable")
	}
	for _, call := range []func() error{
		func() error { _, e := w.View(); return e }, func() error { _, e := w.Pull(context.Background()); return e },
		func() error {
			_, e := w.SetVariable(context.Background(), "env", "UNIT", "no-write", "blocked-write")
			return e
		},
		func() error { _, e := w.ApprovalInfo(); return e }, func() error { _, e := w.ApprovePairing(context.Background(), ApprovalInput{}); return e },
		func() error { _, e := w.RetryApproval(context.Background(), "blocked-pairing"); return e }, func() error { return w.CancelApproval("blocked-pairing") },
	} {
		if e := call(); !errors.Is(e, ErrRecoveryRestricted) {
			t.Fatal("restricted context bypassed gate", e)
		}
	}
	if e := w.Logout(); e != nil {
		t.Fatal(e)
	}
	var closed protectedState
	if json.Unmarshal(saved, &closed) != nil || closed.Recovery != nil || !closed.Cloud.AccountClosed || closed.Root != nil || bytes.Contains(saved, []byte("synthetic-recovered-unit-value")) {
		t.Fatal("logout retained restricted cache/token")
	}
}
func TestRecoveryExpiredBearerScrubPersistsAndCannotReopenByClockRollback(t *testing.T) {
	config, state := recoveryStateFixture(t)
	var saved []byte
	config.SaveProtectedState = func(b []byte) error { saved = bytes.Clone(b); return nil }
	config.Now = func() time.Time { return time.Unix(state.Recovery.SessionExpiresAt+1, 0) }
	config.ProtectedState = selfMust(json.Marshal(state))
	w := selfMust(New(config))
	defer w.Close()
	info := selfMust(w.RecoveryInfo())
	if info.State != "expired-pending" || info.TrustedDevice {
		t.Fatal(info)
	}
	if _, e := w.RecoveryView(); !errors.Is(e, ErrRecoveryExpired) {
		t.Fatal("expired recovery retained readable plaintext", e)
	}
	var expired protectedState
	if json.Unmarshal(saved, &expired) != nil || expired.Recovery.SessionToken != "" || !expired.Recovery.SessionClosed {
		t.Fatal("expired bearer not scrubbed before metadata result")
	}
	config.Now = func() time.Time { return time.Unix(state.Recovery.CreatedAt+10, 0) }
	config.ProtectedState = saved
	if reopened, e := New(config); e == nil {
		reopened.Close()
		t.Fatal("clock rollback reopened expired native context")
	}
}
