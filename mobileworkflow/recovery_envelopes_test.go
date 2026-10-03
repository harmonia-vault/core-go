package mobileworkflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
)

func TestRecoveryEmptyInitialEnvelopeRequiresExactOriginalTwoSignatureCommitment(t *testing.T) {
	_, state := recoveryStateFixture(t)
	v := state.Recovery.Vault
	v.Events = nil // No AEAD plaintext can detect the forged environment key.
	if err := verifyRecoveryEnvelopes(v, *v.TrustRoot, false); err != nil {
		t.Fatal(err)
	}
	forged := selfMust(cryptox.WrapEnvironmentKey(bytes.Repeat([]byte{91}, 32), cryptox.EnvelopeContext{AccountID: v.AccountID, AccountGeneration: v.AccountGeneration, EnvironmentID: "env", KeyVersion: "1", RecipientType: "recovery", RecipientID: v.AccountID, RecipientGeneration: "1", RecipientPublicKey: v.RecoveryReceivingPublicKey}))
	v.Environments[0].Envelope = cryptox.EncodeBase64(forged)
	if err := verifyRecoveryEnvelopes(v, *v.TrustRoot, false); !errors.Is(err, ErrRecoveryEvidence) {
		t.Fatal("public HPKE wrapping authenticated a sender", err)
	}
}

func TestRecoveryEmptyRotatedEnvelopeRequiresCompleteNewCodeSignedManifest(t *testing.T) {
	config, state := recoveryStateFixture(t)
	original := state.Recovery.Vault
	oldRoot := *original.TrustRoot
	seed := bytes.Repeat([]byte{73}, 32)
	defer clear(seed)
	key := selfMust(cryptox.DecodeBase64(state.Recovery.Keys["env"], 32, 32))
	defer clear(key)
	next := selfMust(cryptox.DeriveRecoveryKeys(seed, original.AccountID, original.AccountGeneration, "2"))
	defer clear(next.SigningPrivate)
	defer clear(next.ReceivingPrivate)
	root := oldRoot
	root.RecoveryGeneration = "2"
	root.RecoverySigningPublicKey = cryptox.EncodeBase64(next.SigningPublic)
	root.RecoveryReceivingPublicKey = cryptox.EncodeBase64(next.ReceivingPublic)
	root = selfMust(cryptox.SignTrustRoot(original.AccountID, original.AccountGeneration, root, next.SigningPrivate))
	packet := selfMust(cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: original.AccountID, AccountGeneration: original.AccountGeneration, EnvironmentID: "env", KeyVersion: "1", RecipientType: "recovery", RecipientID: original.AccountID, RecipientGeneration: "2", RecipientPublicKey: root.RecoveryReceivingPublicKey}))
	proposal := cryptox.RecoveryRotationProposal{IdempotencyKey: "unit-envelope-rotation", NewRecoveryGeneration: "2", NewRecoverySigningPublicKey: root.RecoverySigningPublicKey, NewRecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, Envelopes: []cryptox.RecoveryEnvelope{{EnvironmentID: "env", KeyVersion: "1", Envelope: cryptox.EncodeBase64(packet)}}, NewTrustRoot: root}
	proof := selfMust(cryptox.NewRecoveryRotationProof(original.AccountID, original.AccountGeneration, state.Recovery.SessionToken, "unit-envelope-challenge", cryptox.EncodeBase64(bytes.Repeat([]byte{55}, 32)), strconv.FormatInt(config.Now().Unix()+100, 10), proposal, oldRoot))
	sig := selfMust(cryptox.SignRecoveryRotationProof(proof, next.SigningPrivate))
	v := clone(original)
	v.Sequence = 3
	v.Events = nil
	v.RecoveryGeneration = "2"
	v.RecoverySigningPublicKey = root.RecoverySigningPublicKey
	v.RecoveryReceivingPublicKey = root.RecoveryReceivingPublicKey
	v.TrustRoot = &root
	v.Environments = clone(proposal.Envelopes)
	v.EnvelopeEvidence = &recoveryEnvelopeEvidence{Profile: "harmonia/recovery-envelope-evidence/v1", EnvironmentChanges: []recoveryEnvelopeChange{}, RecoveryRotations: []recoveryEnvelopeRotation{{Sequence: 3, Proposal: proposal, Proof: proof, Signature: sig}}}
	if err := verifyRecoveryEnvelopes(v, root, false); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		mutate func(*recoveryVaultWire)
	}{
		{"missing-evidence", func(v *recoveryVaultWire) { v.EnvelopeEvidence = nil }},
		{"missing-rotation", func(v *recoveryVaultWire) { v.EnvelopeEvidence.RecoveryRotations = []recoveryEnvelopeRotation{} }},
		{"forged-ciphertext", func(v *recoveryVaultWire) {
			v.Environments[0].Envelope = cryptox.EncodeBase64(bytes.Repeat([]byte{92}, 80))
		}},
		{"rewrite-ciphertext-and-rehash", func(v *recoveryVaultWire) {
			e := &v.EnvelopeEvidence.RecoveryRotations[0]
			e.Proposal.Envelopes[0].Envelope = cryptox.EncodeBase64(bytes.Repeat([]byte{92}, 80))
			v.Environments = clone(e.Proposal.Envelopes)
			e.Proof.EnvelopesHash = selfMust(cryptox.RecoveryEnvelopesHash(e.Proposal.Envelopes))
		}},
		{"foreign-account", func(v *recoveryVaultWire) { v.EnvelopeEvidence.RecoveryRotations[0].Proof.AccountID = "other-account" }},
		{"foreign-new-code", func(v *recoveryVaultWire) {
			v.EnvelopeEvidence.RecoveryRotations[0].Proof.NewRecoverySigningPublicKey = oldRoot.RecoverySigningPublicKey
		}},
		{"foreign-root", func(v *recoveryVaultWire) {
			v.EnvelopeEvidence.RecoveryRotations[0].Proposal.NewTrustRoot.RootDeviceID = "other-root"
		}},
		{"duplicate-manifest", func(v *recoveryVaultWire) {
			e := v.EnvelopeEvidence.RecoveryRotations[0]
			v.EnvelopeEvidence.RecoveryRotations = append(v.EnvelopeEvidence.RecoveryRotations, e)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bad := clone(v)
			tt.mutate(&bad)
			if err := verifyRecoveryEnvelopes(bad, root, false); !errors.Is(err, ErrRecoveryEvidence) {
				t.Fatal("unproven rotated envelope accepted", err)
			}
		})
	}
}

// A rejected ciphertext commitment must stop before the HPKE receiving key is
// even required. This catches a decode-first implementation independently of AEAD.
func TestRecoveryEnvelopeCommitmentRejectedBeforeHPKE(t *testing.T) {
	config, state := recoveryStateFixture(t)
	config.ProtectedState = selfMust(json.Marshal(state))
	w := selfMust(New(config))
	defer w.Close()
	seed := bytes.Repeat([]byte{17}, 32)
	defer clear(seed)
	keys := selfMust(cryptox.DeriveRecoveryKeys(seed, state.AccountID, state.AccountGeneration, "1"))
	defer clear(keys.SigningPrivate)
	clear(keys.ReceivingPrivate)
	keys.ReceivingPrivate = nil
	v := clone(state.Recovery.Vault)
	v.Environments[0].Envelope = cryptox.EncodeBase64(bytes.Repeat([]byte{91}, 80))
	if _, err := w.openRecoveryVault(v, keys, "1", nil); !errors.Is(err, ErrRecoveryEvidence) {
		t.Fatal("unauthenticated commitment reached HPKE processing", err)
	}
}
