package cryptox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

// 两段真实 new-only 轮换把代际从 1 推到 3；管理者恢复连续链时
// 不得把第一段的 Ed 或 X 公钥重新用于代际 4。
func TestRecoveryAuthorityReanchorRejectsSameGapIntermediateKeyReuse(t *testing.T) {
	f := makeRecoveryAuthorityFixture(t)
	v, err := VerifyRecoveryInitialization(f.RootPin, f.Original)
	recoveryCheck(t, err)
	now := time.Unix(f.SyntheticNow, 0)
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	intermediate, err := DeriveRecoveryKeys(bytes.Repeat([]byte{67}, 32), f.RootPin.AccountID, "1", "2")
	recoveryCheck(t, err)
	last, err := DeriveRecoveryKeys(bytes.Repeat([]byte{68}, 32), f.RootPin.AccountID, "1", "3")
	recoveryCheck(t, err)
	fresh, err := DeriveRecoveryKeys(bytes.Repeat([]byte{69}, 32), f.RootPin.AccountID, "1", "4")
	recoveryCheck(t, err)

	legacy := recoveryClone(t, *f.Reanchor.Submission.LegacyState)
	var fields []string
	encoded, err := DecodeBase64(legacy.Rotations[0].SigningBytes, 1, 4096)
	recoveryCheck(t, err)
	recoveryCheck(t, json.Unmarshal(encoded, &fields))
	lastRoot := f.Reanchor.Submission.NewTrustRoot
	lastRootHash, err := lastRoot.Hash(f.RootPin.AccountID, "1")
	recoveryCheck(t, err)
	second := RecoveryRotationProof{AccountID: f.RootPin.AccountID, AccountGeneration: "1", SessionHash: fields[3], RecoveryGeneration: "2", ChallengeID: "legacy-challenge-second", Nonce: fields[6], ExpiresAt: fields[7], NewRecoveryGeneration: "3", NewRecoverySigningPublicKey: EncodeBase64(last.SigningPublic), NewRecoveryReceivingPublicKey: EncodeBase64(last.ReceivingPublic), EnvelopesHash: fields[11], TrustRootHash: lastRootHash}
	secondSignature, err := SignRecoveryRotationProof(second, last.SigningPrivate)
	recoveryCheck(t, err)
	secondBytes, err := second.SigningBytes()
	recoveryCheck(t, err)
	legacy.Rotations = append(legacy.Rotations, RecoveryLegacyRotation{IdempotencyKey: "legacy-v1-second", SigningBytes: EncodeBase64(secondBytes), Signature: secondSignature, Sequence: 15})
	legacy.RecoveryGeneration = "3"
	legacy.RecoverySigningPublicKey = EncodeBase64(last.SigningPublic)
	legacy.RecoveryReceivingPublicKey = EncodeBase64(last.ReceivingPublic)
	legacy.TrustRoot = lastRoot
	legacyHash, err := legacy.Hash(f.RootPin.AccountID, "1")
	recoveryCheck(t, err)

	prepare := func(signing ed25519.PrivateKey, receiving string) RecoveryTransitionSubmission {
		s := recoveryClone(t, f.Reanchor.Submission)
		s.LegacyState = &legacy
		s.Transition.LegacyStateHash = legacyHash
		s.Transition.OldRecoveryGeneration = "3"
		s.Transition.OldRecoverySigningPublicKey = legacy.RecoverySigningPublicKey
		s.Transition.OldRecoveryReceivingPublicKey = legacy.RecoveryReceivingPublicKey
		s.Transition.NewRecoveryGeneration = "4"
		s.Transition.NewRecoverySigningPublicKey = EncodeBase64(signing.Public().(ed25519.PublicKey))
		s.Transition.NewRecoveryReceivingPublicKey = receiving
		s.NewTrustRoot.RecoveryGeneration = "4"
		s.NewTrustRoot.RecoverySigningPublicKey = s.Transition.NewRecoverySigningPublicKey
		s.NewTrustRoot.RecoveryReceivingPublicKey = receiving
		s.NewTrustRoot, err = SignTrustRoot(f.RootPin.AccountID, "1", s.NewTrustRoot, signing)
		recoveryCheck(t, err)
		s.Transition.NewTrustRootHash, err = RecoveryTrustRootReferenceHash(f.RootPin.AccountID, "1", s.NewTrustRoot)
		recoveryCheck(t, err)
		s.IssuerEvidence.TrustRoot = lastRoot
		s.Transition.IssuerEvidenceHash, err = RecoveryIssuerEvidenceHash(*s.IssuerEvidence)
		recoveryCheck(t, err)
		s.Envelopes = []RecoveryEnvelope{}
		for _, row := range s.EnvironmentManifest {
			packet, e := WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), EnvelopeContext{AccountID: f.RootPin.AccountID, AccountGeneration: "1", EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion, RecipientType: "recovery", RecipientID: f.RootPin.AccountID, RecipientGeneration: "4", RecipientPublicKey: receiving})
			recoveryCheck(t, e)
			s.Envelopes = append(s.Envelopes, RecoveryEnvelope{EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion, Envelope: EncodeBase64(packet)})
		}
		s.Transition.EnvelopesHash, err = RecoveryTransitionEnvelopesHash(s.Envelopes)
		recoveryCheck(t, err)
		return s
	}

	t.Run("fresh-keys-still-accepted", func(t *testing.T) {
		s := prepare(fresh.SigningPrivate, EncodeBase64(fresh.ReceivingPublic))
		s.AuthorizationSignature, err = SignAllAdminRecoveryTransition(v, s, manager, now)
		recoveryCheck(t, err)
		s.NewRecoverySignature, err = SignNewRecoveryTransition(v, s, fresh.SigningPrivate, now)
		recoveryCheck(t, err)
		_, err = VerifyAcceptedRecoveryTransition(v, AcceptedRecoveryTransition{Submission: s, Sequence: 22})
		recoveryCheck(t, err)
	})
	for _, name := range []string{"intermediate-signing", "intermediate-receiving"} {
		t.Run(name, func(t *testing.T) {
			signing, receiving := fresh.SigningPrivate, EncodeBase64(fresh.ReceivingPublic)
			if name == "intermediate-signing" {
				signing = intermediate.SigningPrivate
			} else {
				receiving = EncodeBase64(intermediate.ReceivingPublic)
			}
			s := prepare(signing, receiving)
			if _, e := SignAllAdminRecoveryTransition(v, s, manager, now); e == nil {
				t.Error("manager signed a proposal reusing an intermediate legacy public key")
			}
			wire, e := s.Transition.SigningBytes()
			recoveryCheck(t, e)
			// 双签真实有效，拒绝必须来自公钥用途检查。
			s.AuthorizationSignature, e = sign(manager, wire)
			recoveryCheck(t, e)
			if _, e = SignNewRecoveryTransition(v, s, signing, now); e == nil {
				t.Error("new key signed a proposal reusing an intermediate legacy public key")
			}
			s.NewRecoverySignature, e = sign(signing, wire)
			recoveryCheck(t, e)
			if _, e = VerifyAcceptedRecoveryTransition(v, AcceptedRecoveryTransition{Submission: s, Sequence: 22}); e == nil {
				t.Error("a valid two-signature packet recycled an intermediate legacy public key")
			}
		})
	}
	if v.Generation() != "1" || v.HeadHash() != f.InitializationHash {
		t.Fatal("candidate validation mutated the previously trusted chain")
	}
}
