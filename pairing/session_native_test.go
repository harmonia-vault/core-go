//go:build harmonia_boringssl && cgo && (darwin || linux)

package pairing

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
)

func pair(t *testing.T, cA, cB Context, codeA, codeB []byte) (a, b *Session, msgA, msgB []byte) {
	t.Helper()
	a, msgA, err := NewInitiator(cA, codeA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	b, msgB, err = NewApprover(cB, codeB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return
}

func confirmedPair(t *testing.T) (a, b *Session) {
	t.Helper()
	c := fixtureContext(time.Now())
	a, b, mA, mB := pair(t, c, c, []byte("12345678"), []byte("12345678"))
	if _, err := a.SessionKey(); !errors.Is(err, ErrState) {
		t.Fatal("未交换消息即返回通道钥")
	}
	confirmA, err := a.Complete(mB)
	if err != nil {
		t.Fatal(err)
	}
	confirmB, err := b.Complete(mA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SessionKey(); !errors.Is(err, ErrState) {
		t.Fatal("未确认即返回通道钥")
	}
	if err := a.VerifyPeerConfirmation(confirmB); err != nil {
		t.Fatal(err)
	}
	if err := b.VerifyPeerConfirmation(confirmA); err != nil {
		t.Fatal(err)
	}
	return
}

func TestNativeRoundTripAndKeyGate(t *testing.T) {
	a, b := confirmedPair(t)
	keyA, err := a.SessionKey()
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := b.SessionKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(keyA) != 32 || !bytes.Equal(keyA, keyB) {
		t.Fatal("配对通道钥不一致")
	}
	keyA[0] ^= 1
	fresh, err := a.SessionKey()
	if err != nil || !bytes.Equal(fresh, keyB) {
		t.Fatal("调用方修改了内部通道钥")
	}
	a.Close()
	if _, err := a.SessionKey(); !errors.Is(err, ErrState) {
		t.Fatal("关闭后仍返回钥")
	}
}

func TestWrongCodeFailsExplicitConfirmation(t *testing.T) {
	c := fixtureContext(time.Now())
	a, b, mA, mB := pair(t, c, c, []byte("12345678"), []byte("87654321"))
	x, err := a.Complete(mB)
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.Complete(mA)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(a.VerifyPeerConfirmation(y), ErrConfirmation) || !errors.Is(b.VerifyPeerConfirmation(x), ErrConfirmation) {
		t.Fatal("错误短码通过确认")
	}
	if _, err := a.SessionKey(); err == nil {
		t.Fatal("错误短码得到通道钥")
	}
}

func TestReflectionAndSingleUse(t *testing.T) {
	c := fixtureContext(time.Now())
	a, b, mA, mB := pair(t, c, c, []byte("12345678"), []byte("12345678"))
	if _, err := a.Complete(mA); !errors.Is(err, ErrReflection) {
		t.Fatal("反射自身消息未拒绝")
	}
	if _, err := a.Complete(mB); !errors.Is(err, ErrState) {
		t.Fatal("失败消息未消费状态")
	}
	if _, err := b.Complete(mA); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Complete(mA); !errors.Is(err, ErrState) {
		t.Fatal("重复处理SPAKE2消息")
	}
	if _, err := b.SessionKey(); err == nil {
		t.Fatal("未确认即有钥")
	}
}

func TestEveryContextFieldRejectsSubstitution(t *testing.T) {
	for i := 0; i < reflect.TypeFor[Context]().NumField(); i++ {
		field := reflect.TypeFor[Context]().Field(i).Name
		t.Run(field, func(t *testing.T) {
			original := fixtureContext(time.Now())
			changed := original
			v := reflect.ValueOf(&changed).Elem().Field(i)
			switch field {
			case "Purpose":
				v.SetString("reset-account")
			case "AccountGeneration":
				v.SetString("2")
			case "ExpiresAt":
				v.SetString(original.ExpiresAt[:len(original.ExpiresAt)-1] + "8")
			case "ChallengeNonce", "InitiatorSigningPublicKey", "InitiatorReceivingPublicKey", "ApproverSigningPublicKey", "ApproverReceivingPublicKey":
				v.SetString(cryptox.EncodeBase64(fixtureBytes(32, 170)))
			default:
				v.SetString(v.String() + "-other")
			}
			if field == "ExpiresAt" && changed.ExpiresAt == original.ExpiresAt {
				v.SetString(original.ExpiresAt[:len(original.ExpiresAt)-1] + "9")
			}
			if changed.ValidateAt(time.Now()) != nil {
				return
			}
			a, b, mA, mB := pair(t, original, changed, []byte("12345678"), []byte("12345678"))
			x, err := a.Complete(mB)
			if err != nil {
				return
			}
			y, err := b.Complete(mA)
			if err != nil {
				return
			}
			if a.VerifyPeerConfirmation(y) == nil || b.VerifyPeerConfirmation(x) == nil {
				t.Fatal("替换上下文通过确认")
			}
		})
	}
}

func TestConfirmationReflectionExpiryAndReplay(t *testing.T) {
	c := fixtureContext(time.Now())
	a, b, mA, mB := pair(t, c, c, []byte("12345678"), []byte("12345678"))
	x, err := a.Complete(mB)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Complete(mA)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(a.VerifyPeerConfirmation(x), ErrConfirmation) {
		t.Fatal("反射本端确认未拒绝")
	}
	c = fixtureContext(time.Now())
	a, b, mA, mB = pair(t, c, c, []byte("12345678"), []byte("12345678"))
	x, err = a.Complete(mB)
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.Complete(mA)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyPeerConfirmation(y); err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyPeerConfirmation(y); !errors.Is(err, ErrState) {
		t.Fatal("确认重放未拒绝")
	}
	b.clock = func() time.Time { return time.Now().Add(3 * time.Minute) }
	if !errors.Is(b.VerifyPeerConfirmation(x), ErrExpired) {
		t.Fatal("到期确认未拒绝")
	}
	if _, err := b.SessionKey(); err == nil {
		t.Fatal("到期后有通道钥")
	}
}

func TestMalformedMessagesAndCorruptedConfirmation(t *testing.T) {
	for _, peer := range [][]byte{nil, make([]byte, 31), make([]byte, 33), bytes.Repeat([]byte{255}, 32)} {
		c := fixtureContext(time.Now())
		a, _, _, _ := pair(t, c, c, []byte("12345678"), []byte("12345678"))
		if _, err := a.Complete(peer); err == nil {
			if a.VerifyPeerConfirmation(make([]byte, 32)) == nil {
				t.Fatal("恶意消息通过持钥确认")
			}
		}
		if _, err := a.SessionKey(); err == nil {
			t.Fatal("恶意消息得到通道钥")
		}
	}
	c := fixtureContext(time.Now())
	a, b, mA, mB := pair(t, c, c, []byte("12345678"), []byte("12345678"))
	_, err := a.Complete(mB)
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.Complete(mA)
	if err != nil {
		t.Fatal(err)
	}
	y[0] ^= 1
	if !errors.Is(a.VerifyPeerConfirmation(y), ErrConfirmation) {
		t.Fatal("篡改确认未拒绝")
	}
}
