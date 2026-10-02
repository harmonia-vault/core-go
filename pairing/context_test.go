package pairing

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
)

func fixtureBytes(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}
func fixtureContext(now time.Time) Context {
	initiator := ed25519.NewKeyFromSeed(fixtureBytes(32, 0)).Public().(ed25519.PublicKey)
	approver := ed25519.NewKeyFromSeed(fixtureBytes(32, 64)).Public().(ed25519.PublicKey)
	a, _ := ecdh.X25519().NewPrivateKey(fixtureBytes(32, 32))
	b, _ := ecdh.X25519().NewPrivateKey(fixtureBytes(32, 96))
	return Context{"account-test", "1", PurposeEnrollment, "pairing-test-1", cryptox.EncodeBase64(fixtureBytes(32, 128)), strconv.FormatInt(now.Unix()+90, 10), "device-new", cryptox.EncodeBase64(initiator), cryptox.EncodeBase64(a.PublicKey().Bytes()), "device-admin", cryptox.EncodeBase64(approver), cryptox.EncodeBase64(b.PublicKey().Bytes())}
}

func TestContextStructureExpiryAndIdentityBinding(t *testing.T) {
	now := time.Now()
	c := fixtureContext(now)
	if err := c.ValidateAt(now); err != nil {
		t.Fatal(err)
	}
	a, err := c.identity("initiator")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.identity("approver")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("角色身份未分离")
	}
	expired := c
	expired.ExpiresAt = strconv.FormatInt(now.Unix(), 10)
	if !errors.Is(expired.ValidateAt(now), ErrExpired) {
		t.Fatal("到期上下文未关闭")
	}
	long := c
	long.ExpiresAt = strconv.FormatInt(now.Unix()+121, 10)
	if !errors.Is(long.ValidateAt(now), ErrContext) {
		t.Fatal("接受超长挑战")
	}
	bad := c
	bad.Purpose = "recover-vault"
	if bad.ValidateAt(now) == nil {
		t.Fatal("用途未限制")
	}
	bad = c
	bad.AccountGeneration = "01"
	if bad.ValidateAt(now) == nil {
		t.Fatal("代际非规范")
	}
	bad = c
	bad.InitiatorDeviceID = c.ApproverDeviceID
	if bad.ValidateAt(now) == nil {
		t.Fatal("接受同设备配对")
	}
	bad = c
	bad.InitiatorReceivingPublicKey = c.InitiatorSigningPublicKey
	if bad.ValidateAt(now) == nil {
		t.Fatal("接受公钥混用")
	}
	bad = c
	bad.InitiatorSigningPublicKey += "="
	if bad.ValidateAt(now) == nil {
		t.Fatal("接受有padding公钥")
	}
}

func TestShortCodeAndDefaultGate(t *testing.T) {
	code, err := GenerateShortCode()
	if err != nil || !validCode(code) {
		t.Fatalf("短码生成失败 %v", err)
	}
	for _, bad := range [][]byte{nil, []byte("1234567"), []byte("123456789"), []byte("1234abcd")} {
		if validCode(bad) {
			t.Fatal("接受非规范短码")
		}
	}
	if !NativeAvailable() {
		if _, _, err := NewInitiator(fixtureContext(time.Now()), code); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("默认配对未关闭: %v", err)
		}
	}
}
