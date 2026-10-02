package cryptox

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

type lifecycleVector struct {
	OldSeed            string                   `json:"syntheticOldRecoverySeedHex"`
	NewSeed            string                   `json:"syntheticNewRecoverySeedHex"`
	SessionToken       string                   `json:"syntheticSessionToken"`
	Prior              TrustRoot                `json:"priorTrustRoot"`
	RecoveryProof      RecoveryProof            `json:"recoveryProof"`
	RecoverySigningHex string                   `json:"recoverySigningHex"`
	RecoverySignature  string                   `json:"recoverySignature"`
	Proposal           RecoveryRotationProposal `json:"proposal"`
	RotationProof      RecoveryRotationProof    `json:"rotationProof"`
	RotationSigningHex string                   `json:"rotationSigningHex"`
	RotationSignature  string                   `json:"rotationSignature"`
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
	p := v.RotationProof
	constructed, e := NewRecoveryRotationProof(p.AccountID, p.AccountGeneration, v.SessionToken, p.ChallengeID, p.Nonce, p.ExpiresAt, v.Proposal, v.Prior)
	if e != nil || constructed != p {
		t.Fatalf("本地重建完整轮换证明不同: %v", e)
	}
	b, e = p.SigningBytes()
	if e != nil || hex.EncodeToString(b) != v.RotationSigningHex {
		t.Fatal("完整13字段轮换编码不同")
	}
	s, e = SignRecoveryRotationProof(p, newKey.SigningPrivate)
	if e != nil || s != v.RotationSignature {
		t.Fatal("新码轮换标准签名不同")
	}
	if e := VerifyRecoveryRotationProof(p, s, newKey.SigningPublic); e != nil {
		t.Fatal(e)
	}
	if _, e := SignRecoveryRotationProof(p, old.SigningPrivate); e == nil {
		t.Fatal("旧码可以签新代轮换")
	}
	if e := VerifyTrustRoot(p.AccountID, p.AccountGeneration, v.Proposal.NewTrustRoot, newKey.SigningPublic); e != nil {
		t.Fatal(e)
	}
	keyMap := map[string][]byte{}
	for _, k := range v.EnvironmentKeys {
		keyMap[k.EnvironmentID] = mustHex(t, k.KeyHex)
	}
	for _, envelope := range v.Proposal.Envelopes {
		context := EnvelopeContext{p.AccountID, p.AccountGeneration, envelope.EnvironmentID, envelope.KeyVersion, "recovery", p.AccountID, p.NewRecoveryGeneration, p.NewRecoveryReceivingPublicKey}
		packet, e := DecodeBase64(envelope.Envelope, 80, 80)
		if e != nil {
			t.Fatal(e)
		}
		key, e := UnwrapEnvironmentKey(newKey.ReceivingPrivate, context, packet)
		if e != nil || !bytes.Equal(key, keyMap[envelope.EnvironmentID]) {
			t.Fatalf("轮换真实恢复封套不同: %v", e)
		}
		if _, e := UnwrapEnvironmentKey(old.ReceivingPrivate, context, packet); e == nil {
			t.Fatal("旧码解开新恢复封套")
		}
	}
}

func TestRecoveryLifecycleAllBindingsAndRootPreservation(t *testing.T) {
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
	for i := 0; i < reflect.TypeFor[RecoveryProof]().NumField(); i++ {
		bad := v.RecoveryProof
		f := reflect.ValueOf(&bad).Elem().Field(i)
		switch i {
		case 1, 2:
			f.SetString("2")
		case 4:
			f.SetString(EncodeBase64(fixtureBytes(32, 200)))
		case 5:
			f.SetString("4102444801")
		default:
			f.SetString(f.String() + "-other")
		}
		if VerifyRecoveryProof(bad, v.RecoverySignature, old.SigningPublic) == nil {
			t.Fatalf("恢复字段未绑定 %d", i)
		}
	}
	for i := 0; i < reflect.TypeFor[RecoveryRotationProof]().NumField(); i++ {
		bad := v.RotationProof
		f := reflect.ValueOf(&bad).Elem().Field(i)
		switch i {
		case 1, 3:
			f.SetString("2")
		case 2, 10, 11:
			f.SetString(strings.Repeat("1", 64))
		case 5, 8, 9:
			f.SetString(EncodeBase64(fixtureBytes(32, 200)))
		case 6:
			f.SetString("4102444801")
		case 7:
			f.SetString("3")
		default:
			f.SetString(f.String() + "-other")
		}
		if VerifyRecoveryRotationProof(bad, v.RotationSignature, newKey.SigningPublic) == nil {
			t.Fatalf("轮换字段未绑定 %d", i)
		}
	}
	reversed := append([]RecoveryEnvelope(nil), v.Proposal.Envelopes...)
	reversed[0], reversed[1] = reversed[1], reversed[0]
	h, e := RecoveryEnvelopesHash(reversed)
	if e != nil || h != v.RotationProof.EnvelopesHash {
		t.Fatal("封套顺序改变hash")
	}
	dup := append(reversed, reversed[0])
	if _, e := RecoveryEnvelopesHash(dup); e == nil {
		t.Fatal("重复恢复环境接受")
	}
	p := cloneJSON(t, v.Proposal)
	p.NewTrustRoot.RootDeviceID = "root-substitute"
	r, e := SignTrustRoot("account-test", "1", p.NewTrustRoot, newKey.SigningPrivate)
	if e != nil {
		t.Fatal(e)
	}
	p.NewTrustRoot = r
	proof := v.RotationProof
	if _, e := NewRecoveryRotationProof(proof.AccountID, proof.AccountGeneration, v.SessionToken, proof.ChallengeID, proof.Nonce, proof.ExpiresAt, p, v.Prior); e == nil {
		t.Fatal("轮换接受新码重签的根替换")
	}
	bad := proof
	bad.TrustRootHash = ""
	if _, e := bad.SigningBytes(); e == nil {
		t.Fatal("接受无manifest降级")
	}
	bad = proof
	bad.RecoveryGeneration = "18446744073709551615"
	bad.NewRecoveryGeneration = "1"
	if _, e := bad.SigningBytes(); e == nil {
		t.Fatal("恢复代际溢出接受")
	}
}
