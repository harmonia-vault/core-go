//go:build harmonia_boringssl && cgo && (darwin || linux || (windows && arm64))

package pairing

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestTranscriptHashRequiresConfirmedFreshSession(t *testing.T) {
	c := fixtureContext(time.Now())
	a, b, mA, mB := pair(t, c, c, []byte("12345678"), []byte("12345678"))
	if _, err := a.TranscriptHash(); !errors.Is(err, ErrState) {
		t.Fatal("交换之前可以导出确认摘要")
	}
	x, err := a.Complete(mB)
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.Complete(mA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.TranscriptHash(); !errors.Is(err, ErrState) {
		t.Fatal("未确认即可导出确认摘要")
	}
	if err := a.VerifyPeerConfirmation(y); err != nil {
		t.Fatal(err)
	}
	if err := b.VerifyPeerConfirmation(x); err != nil {
		t.Fatal(err)
	}
	digest, err := transcriptDigest(c, mA, mB)
	if err != nil {
		t.Fatal(err)
	}
	ha, err := a.TranscriptHash()
	if err != nil || ha != hex.EncodeToString(digest[:]) {
		t.Fatal("确认摘要编码不同")
	}
	hb, err := b.TranscriptHash()
	if err != nil || hb != ha {
		t.Fatal("两端摘要不一致")
	}
	a.Close()
	if _, err := a.TranscriptHash(); !errors.Is(err, ErrState) {
		t.Fatal("关闭后可导出确认摘要")
	}
	b.clock = func() time.Time { return time.Now().Add(3 * time.Minute) }
	if _, err := b.TranscriptHash(); !errors.Is(err, ErrExpired) {
		t.Fatal("到期后可导出确认摘要")
	}
}
