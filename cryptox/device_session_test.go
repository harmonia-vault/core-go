package cryptox

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestDeviceSessionKnownAnswerAndBinding(t *testing.T) {
	b, err := os.ReadFile("testdata/device-session-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Proof            DeviceSessionProof `json:"proof"`
		Signature        string             `json:"signature"`
		SigningHex       string             `json:"signingHex"`
		SigningPublicKey string             `json:"signingPublicKey"`
		SigningSeedHex   string             `json:"syntheticSigningSeedHex"`
		LoginToken       string             `json:"syntheticLoginToken"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	p, err := NewDeviceSessionProof(v.Proof.AccountID, v.Proof.AccountGeneration, v.Proof.DeviceID, v.LoginToken, v.Proof.ChallengeID, v.Proof.Nonce, v.Proof.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if p != v.Proof {
		t.Fatal("client proof construction drift")
	}
	encoded, err := p.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encoded) != v.SigningHex {
		t.Fatal("canonical device session bytes drift")
	}
	pub, err := DecodeBase64(v.SigningPublicKey, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceSessionProof(p, v.Signature, pub); err != nil {
		t.Fatal(err)
	}
	sk := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeedHex))
	sig, err := SignDeviceSessionProof(p, sk)
	if err != nil || sig != v.Signature {
		t.Fatal("known signature mismatch")
	}
	for i := 0; i < reflect.TypeFor[DeviceSessionProof]().NumField(); i++ {
		bad := p
		f := reflect.ValueOf(&bad).Elem().Field(i)
		f.SetString(f.String() + "x")
		if VerifyDeviceSessionProof(bad, v.Signature, pub) == nil {
			t.Fatalf("unbound device session field %d", i)
		}
	}
	bad := p
	bad.LoginTokenHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if VerifyDeviceSessionProof(bad, v.Signature, pub) == nil {
		t.Fatal("accepted another login token")
	}
}
