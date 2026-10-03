package mobileworkflow

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
)

func recoveryTypedAuthorityFixture(t *testing.T) recoveryAuthorityVault {
	t.Helper()
	config, state := recoveryStateFixture(t)
	v := clone(state.Recovery.Vault)
	pin := selfMust(recoveryAuthorityPin(v))
	initial := selfMust(recoveryOriginalRecord(v))
	authority := selfMust(cryptox.VerifyRecoveryInitialization(pin, initial))
	seed := bytes.Repeat([]byte{17}, 32)
	defer clear(seed)
	old := selfMust(cryptox.DeriveRecoveryKeys(seed, v.AccountID, v.AccountGeneration, "1"))
	defer clear(old.SigningPrivate)
	defer clear(old.ReceivingPrivate)
	newSeed := bytes.Repeat([]byte{71}, 32)
	defer clear(newSeed)
	next := selfMust(cryptox.DeriveRecoveryKeys(newSeed, v.AccountID, v.AccountGeneration, "2"))
	defer clear(next.SigningPrivate)
	defer clear(next.ReceivingPrivate)
	root := *v.TrustRoot
	root.RecoveryGeneration = "2"
	root.RecoverySigningPublicKey = cryptox.EncodeBase64(next.SigningPublic)
	root.RecoveryReceivingPublicKey = cryptox.EncodeBase64(next.ReceivingPublic)
	root = selfMust(cryptox.SignTrustRoot(v.AccountID, v.AccountGeneration, root, next.SigningPrivate))
	dataKey := selfMust(cryptox.DecodeBase64(state.Recovery.Keys["env"], 32, 32))
	defer clear(dataKey)
	packet := selfMust(cryptox.WrapEnvironmentKey(dataKey, cryptox.EnvelopeContext{AccountID: v.AccountID, AccountGeneration: v.AccountGeneration, EnvironmentID: "env", KeyVersion: "1", RecipientType: "recovery", RecipientID: v.AccountID, RecipientGeneration: "2", RecipientPublicKey: root.RecoveryReceivingPublicKey}))
	envs := []cryptox.RecoveryEnvelope{{EnvironmentID: "env", KeyVersion: "1", Envelope: cryptox.EncodeBase64(packet)}}
	manifest := []cryptox.RecoveryEnvironmentVersion{{EnvironmentID: "env", KeyVersion: "1"}}
	s := cryptox.RecoveryTransitionSubmission{Transition: cryptox.RecoveryAuthorityTransition{AccountID: v.AccountID, AccountGeneration: v.AccountGeneration, OperationID: "authority-unit", ChallengeID: "authority-unit-challenge", Nonce: cryptox.EncodeBase64(bytes.Repeat([]byte{67}, 32)), ExpiresAt: strconv.FormatInt(config.Now().Unix()+120, 10), SessionHash: state.Recovery.SessionHash, ExpectedSequence: "2", PreviousTransitionHash: authority.HeadHash(), OldRecoveryGeneration: "1", OldRecoverySigningPublicKey: v.RecoverySigningPublicKey, OldRecoveryReceivingPublicKey: v.RecoveryReceivingPublicKey, NewRecoveryGeneration: "2", NewRecoverySigningPublicKey: root.RecoverySigningPublicKey, NewRecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, AuthorizationKind: "old-recovery", EnvironmentManifestHash: selfMust(cryptox.RecoveryManifestHash(manifest)), EnvelopesHash: selfMust(cryptox.RecoveryTransitionEnvelopesHash(envs)), NewTrustRootHash: selfMust(cryptox.RecoveryTrustRootReferenceHash(v.AccountID, v.AccountGeneration, root)), ChainMode: "continuous"}, EnvironmentManifest: manifest, AuthoritySet: []cryptox.RecoveryAdminAuthority{}, Envelopes: envs, NewTrustRoot: root}
	s.AuthorizationSignature = selfMust(cryptox.SignOldRecoveryTransition(authority, s, old.SigningPrivate, config.Now()))
	s.NewRecoverySignature = selfMust(cryptox.SignNewRecoveryTransition(authority, s, next.SigningPrivate, config.Now()))
	v.Sequence = 3
	v.RecoveryGeneration = "2"
	v.RecoverySigningPublicKey = root.RecoverySigningPublicKey
	v.RecoveryReceivingPublicKey = root.RecoveryReceivingPublicKey
	v.TrustRoot = &root
	v.Environments = envs
	return recoveryAuthorityVault{recoveryVaultWire: v, Transitions: []cryptox.AcceptedRecoveryTransition{{Submission: s, Sequence: 3}}}
}

func TestRecoveryAuthorityContinuityAndEmptyEnvelopeCannotUseServerCurrentPublicKey(t *testing.T) {
	good := recoveryTypedAuthorityFixture(t)
	if _, err := verifyAuthorityEnvelopeCommitments(good); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		mutate func(*recoveryAuthorityVault)
	}{
		{"missing-chain", func(v *recoveryAuthorityVault) { v.Transitions = []cryptox.AcceptedRecoveryTransition{} }},
		{"missing-old-signature", func(v *recoveryAuthorityVault) {
			v.Transitions[0].Submission.AuthorizationSignature = cryptox.EncodeBase64(make([]byte, 64))
		}},
		{"rewritten-full-hash", func(v *recoveryAuthorityVault) {
			s := &v.Transitions[0].Submission
			s.Envelopes[0].Envelope = cryptox.EncodeBase64(bytes.Repeat([]byte{91}, 80))
			v.Environments = clone(s.Envelopes)
			s.Transition.EnvelopesHash = selfMust(cryptox.RecoveryTransitionEnvelopesHash(s.Envelopes))
		}},
		{"valid-chain-wrong-current-cipher", func(v *recoveryAuthorityVault) {
			v.Environments[0].Envelope = cryptox.EncodeBase64(bytes.Repeat([]byte{91}, 80))
		}},
		{"wrong-root", func(v *recoveryAuthorityVault) {
			v.TrustRoot.RootSigningPublicKey = cryptox.EncodeBase64(bytes.Repeat([]byte{91}, 32))
		}},
		{"different-head", func(v *recoveryAuthorityVault) {
			v.Transitions[0].Submission.Transition.PreviousTransitionHash = string(bytes.Repeat([]byte{'0'}, 64))
		}},
		{"wrong-sequence", func(v *recoveryAuthorityVault) { v.Transitions[0].Sequence++ }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := clone(good)
			tt.mutate(&v)
			if _, err := verifyAuthorityEnvelopeCommitments(v); !errors.Is(err, ErrRecoveryEvidence) {
				t.Fatal("unauthenticated authority source accepted", err)
			}
		})
	}
}
