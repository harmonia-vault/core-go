package cryptox

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestDeviceBootKnownAnswerAndEveryFieldBinding(t *testing.T) {
	data, err := os.ReadFile("testdata/device-boot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Proof      DeviceBootProof `json:"proof"`
		Signature  string          `json:"signature"`
		SigningHex string          `json:"signingHex"`
		SeedHex    string          `json:"syntheticSigningSeedHex"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	sk := ed25519.NewKeyFromSeed(mustHex(t, v.SeedHex))
	pub := sk.Public().(ed25519.PublicKey)
	encoded, err := v.Proof.SigningBytes()
	if err != nil || hex.EncodeToString(encoded) != v.SigningHex {
		t.Fatalf("启动证明编码不同: %v", err)
	}
	sig, err := SignDeviceBootProof(v.Proof, sk)
	if err != nil || sig != v.Signature {
		t.Fatalf("启动证明签名不同: %v", err)
	}
	if err := VerifyDeviceBootProof(v.Proof, sig, pub); err != nil {
		t.Fatal(err)
	}
	other := fixtureBytes(32, 200)
	for i := 0; i < reflect.TypeFor[DeviceBootProof]().NumField(); i++ {
		bad := v.Proof
		field := reflect.ValueOf(&bad).Elem().Field(i)
		switch i {
		case 1:
			field.SetString("2")
		case 3, 4, 6:
			field.SetString(EncodeBase64(other))
		case 7:
			field.SetString("4102444801")
		default:
			field.SetString(field.String() + "-other")
		}
		if VerifyDeviceBootProof(bad, sig, pub) == nil {
			t.Fatalf("未绑定启动字段 %d", i)
		}
	}
	bad := v.Proof
	bad.SigningPublicKey = EncodeBase64(other)
	if _, err := SignDeviceBootProof(bad, sk); err == nil {
		t.Fatal("接受签名钥与声明公钥不一致")
	}
	for _, value := range []string{"0", "01", "-1"} {
		bad = v.Proof
		bad.AccountGeneration = value
		if _, err := bad.SigningBytes(); err == nil {
			t.Fatal("接受非规范账号代际")
		}
	}
	bad = v.Proof
	bad.Nonce += "="
	if _, err := bad.SigningBytes(); err == nil {
		t.Fatal("接受带padding挑战")
	}
	bad = v.Proof
	bad.ReceivingPublicKey = bad.SigningPublicKey
	if _, err := bad.SigningBytes(); err == nil {
		t.Fatal("接受独立公钥混用")
	}
}
