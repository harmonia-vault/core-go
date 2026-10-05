package cryptox

import (
	"crypto/ed25519"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestPairingRelayKnownAnswerAndBindings(t *testing.T) {
	var v struct {
		Relay      PairingRelay `json:"relay"`
		SigningHex string       `json:"signingHex"`
		Signature  string       `json:"signature"`
		Seed       string       `json:"syntheticSigningSeedHex"`
	}
	readVector(t, "pairing-relay-v1.json", &v)
	sk := ed25519.NewKeyFromSeed(mustHex(t, v.Seed))
	pub := sk.Public().(ed25519.PublicKey)
	b, e := v.Relay.SigningBytes()
	if e != nil || hex.EncodeToString(b) != v.SigningHex {
		t.Fatal("中继固定编码不同")
	}
	s, e := SignPairingRelay(v.Relay, sk)
	if e != nil || s != v.Signature {
		t.Fatal("中继标准签名不同")
	}
	if e := VerifyPairingRelay(v.Relay, s, pub); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < reflect.TypeFor[PairingRelay]().NumField(); i++ {
		bad := v.Relay
		f := reflect.ValueOf(&bad).Elem().Field(i)
		switch i {
		case 1:
			f.SetString("2")
		case 3, 6:
			f.SetString(EncodeBase64(fixtureBytes(32, 20)))
		case 4:
			f.SetString("approver")
		case 5:
			f.SetString("confirmation")
		default:
			f.SetString(f.String() + "-other")
		}
		if VerifyPairingRelay(bad, s, pub) == nil {
			t.Fatalf("中继字段未绑定 %d", i)
		}
	}
	for _, kind := range []string{"shortCode", "password", "confirm", ""} {
		r := v.Relay
		r.Kind = kind
		if _, e := r.SigningBytes(); e == nil {
			t.Fatal("接受秘密或未知中继类型")
		}
	}
	r := v.Relay
	r.Payload = EncodeBase64([]byte("12345678"))
	if _, e := r.SigningBytes(); e == nil {
		t.Fatal("中继接受八位短码payload")
	}
}

func TestEnrollmentApprovalHTTPLayoutAndLimits(t *testing.T) {
	v, anchor := issuerFixture(t)
	if _, e := VerifyCompletedEnrollmentV5(anchor, v.Approval); e != nil {
		t.Fatal(e)
	}
	var e error
	a := v.Approval
	a.Context.Purpose = "reset-account"
	if _, e = a.Certificate(); e == nil {
		t.Fatal("批准对象接受其它用途")
	}
	if _, e := EnrollmentGrantsHash(nil); e == nil {
		t.Fatal("接受零环境授权")
	}
	tooMany := make([]SignedGrantWire, 257)
	if _, e := EnrollmentGrantsHash(tooMany); e == nil {
		t.Fatal("接受超过授权上限")
	}
	var init initializationVector
	readVector(t, "vault-initialization-v1.json", &init)
	p := cloneJSON(t, init.Proposal)
	p.Environments = nil
	if _, e = p.Hash(init.Proof.AccountID, init.Proof.AccountGeneration); e == nil {
		t.Fatal("初始化接受零环境")
	}
	p = cloneJSON(t, init.Proposal)
	p.RecoveryGeneration = "2"
	if _, e = p.Hash(init.Proof.AccountID, init.Proof.AccountGeneration); e == nil {
		t.Fatal("初始化接受恢复代际非1")
	}
	p = cloneJSON(t, init.Proposal)
	p.Environments[0].Grant.Grant.ExpiresAt = "4102444800"
	if _, e = p.Hash(init.Proof.AccountID, init.Proof.AccountGeneration); e == nil {
		t.Fatal("初始自授权接受限时")
	}
}
