//go:build harmonia_boringssl && cgo && (darwin || linux || (windows && arm64))

package pairing

import (
	"errors"
	"testing"
	"time"
)

func TestCrossSessionConfirmationReplayAndExpiredKey(t *testing.T) {
	c := fixtureContext(time.Now())
	a1, b1, mA1, mB1 := pair(t, c, c, []byte("12345678"), []byte("12345678"))
	x1, err := a1.Complete(mB1)
	if err != nil {
		t.Fatal(err)
	}
	y1, err := b1.Complete(mA1)
	if err != nil {
		t.Fatal(err)
	}
	a2, b2, mA2, mB2 := pair(t, c, c, []byte("12345678"), []byte("12345678"))
	if _, err := a2.Complete(mB2); err != nil {
		t.Fatal(err)
	}
	if _, err := b2.Complete(mA2); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(a2.VerifyPeerConfirmation(y1), ErrConfirmation) || !errors.Is(b2.VerifyPeerConfirmation(x1), ErrConfirmation) {
		t.Fatal("另一原生会话的确认值通过")
	}
	if _, err := a2.SessionKey(); err == nil {
		t.Fatal("跨会话重放得到钥")
	}
	if err := a1.VerifyPeerConfirmation(y1); err != nil {
		t.Fatal(err)
	}
	a1.clock = func() time.Time { return time.Now().Add(3 * time.Minute) }
	if _, err := a1.SessionKey(); !errors.Is(err, ErrExpired) {
		t.Fatal("已确认会话到期仍可取钥")
	}
	a3, _, _, mB3 := pair(t, c, c, []byte("12345678"), []byte("12345678"))
	a3.clock = func() time.Time { return time.Now().Add(3 * time.Minute) }
	if _, err := a3.Complete(mB3); !errors.Is(err, ErrExpired) {
		t.Fatal("到期仍处理消息")
	}
}
