package mobileworkflow

import (
	"context"
	"time"
)

// The HTTPS challenge permits five seconds of clock skew. Mature signing still
// requires the unchanged original expiry to be within 120 seconds of this
// device's actual clock. Wait for that horizon; never substitute server time,
// extend a deadline, or modify a signed packet.
func (w *Workflow) waitRecoveredDeviceChallenge(ctx context.Context, expires int64) (err error) {
	defer func() {
		if err != nil && w.recoverySession != nil {
			w.recoverySession.Close()
			w.recoverySession = nil
		}
	}()
	return waitRecoveryChallengeHorizon(ctx, expires, w.now, w.authoritySessionLive)
}

// live may synchronously save the protected clock checkpoint. Check both the
// original monotonic budget and cancellation again after it returns so a slow
// or failed native save cannot permit signing after the waiting budget.
func waitRecoveryChallengeHorizon(ctx context.Context, expires int64, now func() time.Time, live func() error) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(deadline) {
			return ErrRecoveryEvidence
		}
		if err := live(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(deadline) {
			return ErrRecoveryEvidence
		}
		wall := now()
		if expires <= wall.Unix() {
			return ErrRecoveryExpired
		}
		if expires <= wall.Unix()+120 {
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrRecoveryEvidence
		}
		delay := time.Unix(expires-120, 0).Sub(wall)
		if delay > 100*time.Millisecond {
			delay = 100 * time.Millisecond
		}
		if delay > remaining {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
