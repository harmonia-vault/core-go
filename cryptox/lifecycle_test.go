package cryptox

import (
	"encoding/hex"
	"testing"
)

type lifecycleVector struct {
	OldSeed            string        `json:"syntheticOldRecoverySeedHex"`
	NewSeed            string        `json:"syntheticNewRecoverySeedHex"`
	SessionToken       string        `json:"syntheticSessionToken"`
	Prior              TrustRoot     `json:"priorTrustRoot"`
	RecoveryProof      RecoveryProof `json:"recoveryProof"`
	RecoverySigningHex string        `json:"recoverySigningHex"`
	RecoverySignature  string        `json:"recoverySignature"`
	RotationSigningHex string        `json:"rotationSigningHex"`
	RotationSignature  string        `json:"rotationSignature"`
	EnvironmentKeys    []struct {
		EnvironmentID string `json:"environmentId"`
		KeyHex        string `json:"keyHex"`
	} `json:"syntheticEnvironmentKeys"`
}

func TestRecoveryLifecycleKnownAnswersAndNewEnvelopes(t *testing.T) {
	var v lifecycleVector
	readVector(t, "recovery-lifecycle-v1.json", &v)
	old, e := DeriveRecoveryKeys(mustHex(t, v.OldSeed), "account-test", "1", "1")
	if e != nil {
		t.Fatal(e)
	}
	newKey, e := DeriveRecoveryKeys(mustHex(t, v.NewSeed), "account-test", "1", "2")
	if e != nil {
		t.Fatal(e)
	}
	b, e := v.RecoveryProof.SigningBytes()
	if e != nil || hex.EncodeToString(b) != v.RecoverySigningHex {
		t.Fatal("恢复挑战编码不同")
	}
	s, e := SignRecoveryProof(v.RecoveryProof, old.SigningPrivate)
	if e != nil || s != v.RecoverySignature {
		t.Fatal("恢复挑战标准签名不同")
	}
	if e := VerifyRecoveryProof(v.RecoveryProof, s, old.SigningPublic); e != nil {
		t.Fatal(e)
	}
	if VerifyRecoveryProof(v.RecoveryProof, s, newKey.SigningPublic) == nil {
		t.Fatal("恢复挑战接受其它代钥")
	}
}
