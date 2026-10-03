package mobileworkflow

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
)

func TestRecoveryChallengeWaitKeepsStrict120AndOriginalExpiry(t *testing.T) {
	observed := time.Now()
	expires := observed.Unix() + 121
	original := strconv.FormatInt(expires, 10)
	if !errors.Is(cryptox.ValidateRecoveryChallenge(original, observed), cryptox.ErrInvalidWire) {
		t.Fatal("strict signing unexpectedly accepted 121 seconds")
	}
	calls := 0
	err := waitRecoveryChallengeHorizon(context.Background(), expires, time.Now, func() error { calls++; return nil })
	if err != nil || calls < 1 || cryptox.ValidateRecoveryChallenge(original, time.Now()) != nil {
		t.Fatal("natural local-clock wait did not enter the unchanged signing horizon", err)
	}
	if strconv.FormatInt(expires, 10) != original {
		t.Fatal("original expiry changed")
	}
}

func TestRecoveryChallengeWaitFixedClockUsesOneMonotonicBudget(t *testing.T) {
	fixed := time.Now()
	started := time.Now()
	calls := 0
	afterSave := false
	err := waitRecoveryChallengeHorizon(context.Background(), fixed.Unix()+121, func() time.Time {
		if afterSave {
			return fixed.Add(2 * time.Second)
		}
		return fixed
	}, func() error {
		calls++
		if time.Since(started) >= 4900*time.Millisecond {
			// A blocking native save finishes after the original budget; even a
			// subsequently valid wall-clock horizon must not permit signing.
			time.Sleep(200 * time.Millisecond)
			afterSave = true
		}
		return nil
	})
	elapsed := time.Since(started)
	if !errors.Is(err, ErrRecoveryEvidence) || elapsed < 5*time.Second || elapsed > 7*time.Second || calls < 2 {
		t.Fatal("fixed clock escaped original waiting budget", err, elapsed)
	}
}

func TestRecoveryChallengeWaitRechecksCancellationAfterNativeSave(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The live check models a native save which finishes after cancellation;
	// signing would otherwise already be in the allowed horizon.
	err := waitRecoveryChallengeHorizon(ctx, time.Now().Unix()+120, time.Now, func() error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("native save reopened canceled signing", err)
	}
}

func TestRecoveryChallengeWaitNativeSaveFailureRetiresProcessOwner(t *testing.T) {
	w, owner, _ := recoverySessionFixture(t)
	if err := w.AttachRecoverySession(owner); err != nil {
		t.Fatal(err)
	}
	base := w.state.Recovery.LastObservedAt
	w.now = func() time.Time { return time.Unix(base+1, 0) }
	failure := errors.New("synthetic native clock-checkpoint save failure")
	w.saveNative = func([]byte) error { return failure }
	alias := owner.signing
	err := w.waitRecoveredDeviceChallenge(context.Background(), base+122)
	if err == nil || err.Error() != "native protected state persistence failed" || w.recoverySession != nil || w.state.RecoveredDevice != nil {
		t.Fatal("failed native save permitted a packet or hid the failure", err)
	}
	if _, err = owner.Binding(); !errors.Is(err, ErrRecoverySession) {
		t.Fatal("failed save retained process owner", err)
	}
	for _, b := range alias {
		if b != 0 {
			t.Fatal("process signing buffer not cleared")
		}
	}
	if w.state.Recovery.SessionClosed {
		t.Fatal("failed save falsely reported durable session closure")
	}
}
