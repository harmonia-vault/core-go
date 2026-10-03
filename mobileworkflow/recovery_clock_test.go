package mobileworkflow

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestRecoveryPureClockRollbackCannotReopenSessionAndPlaintext(t *testing.T) {
	w, owner, config := recoverySessionFixture(t)
	base := w.state.Recovery.LastObservedAt
	wall := base
	w.now = func() time.Time { return time.Unix(wall, 0) }
	var saved []byte
	w.saveNative = func(data []byte) error { saved = append([]byte(nil), data...); return nil }
	if err := w.AttachRecoverySession(owner); err != nil {
		t.Fatal(err)
	}
	wall = base - 6 // Neither server session nor challenge is at its expiry.
	if _, err := w.RecoveryInfo(); !errors.Is(err, ErrRecoveryExpired) {
		t.Fatal(err)
	}
	wall = base
	if _, err := w.RecoveryView(); !errors.Is(err, ErrRecoveryExpired) {
		t.Fatal("clock recovery reopened plaintext", err)
	}
	if !w.state.Recovery.SessionClosed || w.state.Recovery.SessionToken != "" || len(w.state.Recovery.Keys) != 0 {
		t.Fatal("rollback retained bearer or cache")
	}
	if _, err := owner.Binding(); !errors.Is(err, ErrRecoverySession) {
		t.Fatal("rollback retained process signer", err)
	}
	if len(saved) == 0 {
		t.Fatal("rollback invalidation was not persisted")
	}
	var state protectedState
	if err := json.Unmarshal(saved, &state); err != nil || !state.Recovery.SessionClosed || state.Recovery.SessionToken != "" || len(state.Recovery.Keys) != 0 {
		t.Fatal("durable rollback state retained secret", err)
	}
	config.ProtectedState = saved
	config.Now = func() time.Time { return time.Unix(base, 0) }
	restored, err := New(config)
	if err != nil {
		t.Fatal("closed metadata could not restore safely", err)
	}
	defer restored.Close()
	if _, err := restored.RecoveryView(); !errors.Is(err, ErrRecoveryExpired) {
		t.Fatal("sealed restart reopened plaintext", err)
	}
}
