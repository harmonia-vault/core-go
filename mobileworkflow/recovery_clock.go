package mobileworkflow

import (
	"errors"

	"github.com/harmonia-vault/core-go/cryptox"
)

// A rollback is a permanent closure, not a temporary authorization pause.
// Keep only signed public history/journal for honest unknown-outcome metadata.
func (w *Workflow) closeRecoverySessionForClock() error {
	r := w.state.Recovery
	if r == nil {
		return nil
	}
	changed := !r.SessionClosed || r.SessionToken != "" || len(r.Keys) != 0 || len(r.Vault.Events) != 0 || w.recoverySession != nil
	r.SessionClosed = true
	r.SessionToken = ""
	for id := range r.Keys {
		delete(r.Keys, id)
	}
	r.Keys = nil
	r.Vault.Events = nil
	if w.recoverySession != nil {
		w.recoverySession.Close()
		w.recoverySession = nil
	}
	if changed {
		return w.persist()
	}
	return nil
}

func (w *Workflow) validateClosedRecoveryVault(r *recoveryRecord) error {
	v := r.Vault
	if len(r.Keys) != 0 || len(v.Events) != 0 || v.AccountID != r.AccountID || v.AccountGeneration != r.AccountGeneration || v.Sequence == 0 || v.Sequence > 9007199254740991 || v.TrustRoot == nil || *v.TrustRoot != r.Root || v.RecoveryGeneration != r.RecoveryGeneration || v.RecoverySigningPublicKey != r.SigningPublicKey || v.RecoveryReceivingPublicKey != r.ReceivingPublicKey || len(v.Environments) == 0 || len(v.Environments) > 256 {
		return errors.New("closed recovery retained cache or invalid public context")
	}
	if _, err := cryptox.RecoveryEnvelopesHash(v.Environments); err != nil {
		return err
	}
	if r.OriginsRequired {
		if _, err := w.verifyRecoveryOriginGrants(v, r.Root); err != nil {
			return err
		}
	} else if _, _, err := w.recoveryGenesis(v, r.Root); err != nil {
		return err
	}
	return verifyRecoveryEnvelopes(v, r.Root, r.OriginsRequired)
}
