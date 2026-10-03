package mobileworkflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

func recoverySessionFixture(t *testing.T) (*Workflow, *RecoverySession, Config) {
	t.Helper()
	config, state := recoveryStateFixture(t)
	r := state.Recovery
	r.OriginsRequired = true
	grant := r.Vault.OriginalInitialization.Proposal.Environments[0].Grant
	graph := cryptox.IssuerProofV2{Profile: cryptox.IssuerProofV2Profile, AccountID: state.AccountID, AccountGeneration: state.AccountGeneration, TrustRoot: r.Root, Path: []cryptox.IssuerEnrollment{}, Authorities: []cryptox.IssuerAuthorityV2{{Grant: grant}}, Targets: []cryptox.IssuerTarget{{EnvironmentID: "env", AuthorityHash: selfMust(cryptox.IssuerAuthorityHash(grant))}}, Origins: []cryptox.SignedEnvironmentOrigin{}, IdentityPaths: [][]cryptox.IssuerEnrollment{}}
	r.Vault.IssuerEvidence = selfMust(json.Marshal(graph))
	config.ProtectedState = selfMust(json.Marshal(state))
	w := selfMust(New(config))
	t.Cleanup(w.Close)
	seed := bytes.Repeat([]byte{17}, 32)
	keys := selfMust(cryptox.DeriveRecoveryKeys(seed, state.AccountID, "1", "1"))
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	defer clear(seed)
	owner := selfMust(w.newRecoverySession(keys.SigningPrivate))
	t.Cleanup(owner.Close)
	return w, owner, config
}
func TestRecoverySessionProcessOwnershipAndNoSerialization(t *testing.T) {
	w, owner, config := recoverySessionFixture(t)
	before := selfMust(owner.Binding())
	if before.ExpiresAt > w.now().Unix()+300 || before.SessionHash != w.state.Recovery.SessionHash || before.InitializationProposalHash == "" {
		t.Fatal("owner lost exact binding or bounded expiry")
	}
	if _, err := json.Marshal(owner); err == nil {
		t.Fatal("owner was serialized")
	}
	if got := fmt.Sprintf("%#v", owner); got != "process-only recovery session (opaque)" {
		t.Fatal("opaque owner format exposed internals")
	}
	if err := w.AttachRecoverySession(owner); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if _, err := owner.Binding(); err != nil {
		t.Fatal("per-operation close destroyed registry owner", err)
	}
	reopened := selfMust(New(config))
	defer reopened.Close()
	if err := reopened.AttachRecoverySession(owner); err != nil {
		t.Fatal("same sealed context could not attach", err)
	}
	if err := reopened.Logout(); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Binding(); !errors.Is(err, ErrRecoverySession) {
		t.Fatal("logout retained signer", err)
	}
}
func TestRecoverySessionClosedDeadlineClockAndIdentityCannotRevive(t *testing.T) {
	for _, mode := range []string{"cancel", "monotonic", "wall-expiry", "wall-rollback", "other-context"} {
		t.Run(mode, func(t *testing.T) {
			w, owner, _ := recoverySessionFixture(t)
			keyAlias := owner.signing
			switch mode {
			case "cancel":
				owner.Cancel()
			case "monotonic":
				owner.mu.Lock()
				owner.deadline = time.Now().Add(-time.Second)
				owner.mu.Unlock()
			case "wall-expiry":
				owner.now = func() time.Time { return time.Unix(owner.binding.ExpiresAt, 0) }
			case "wall-rollback":
				owner.now = func() time.Time { return time.Unix(owner.lastWall-6, 0) }
			case "other-context":
				other, _, _ := recoverySessionFixture(t)
				if err := other.AttachRecoverySession(owner); !errors.Is(err, ErrRecoverySession) {
					t.Fatal("cross-root owner attached", err)
				}
				owner.Close()
			}
			if _, err := owner.Binding(); !errors.Is(err, ErrRecoverySession) {
				t.Fatal("invalid owner remained usable", err)
			}
			for _, b := range keyAlias {
				if b != 0 {
					t.Fatal("controlled private buffer was not cleared")
				}
			}
			if err := w.AttachRecoverySession(owner); !errors.Is(err, ErrRecoverySession) {
				t.Fatal("closed owner revived", err)
			}
		})
	}
}
func TestRecoverySessionConcurrentCancelAttachAndClose(t *testing.T) {
	w, owner, _ := recoverySessionFixture(t)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { _ = w.AttachRecoverySession(owner); owner.Cancel(); owner.Close(); _, _ = owner.Binding() })
	}
	wg.Wait()
	if _, err := owner.Binding(); !errors.Is(err, ErrRecoverySession) {
		t.Fatal(err)
	}
}
func TestRecoveryVaultEvidenceClassificationDoesNotMaskTransportOrInvalidation(t *testing.T) {
	for _, tt := range []struct {
		err                   error
		evidence, invalidated bool
	}{
		{errors.New("mobile HTTPS request failed"), false, false},
		{syncclient.NewRequestError(502, "request_rejected"), false, false},
		{syncclient.NewRequestError(403, "request_rejected"), true, false},
		{errors.Join(errMobileResponseMalformed, errors.New("synthetic bad schema")), true, false},
		{syncclient.NewRequestError(401, "unauthorized"), false, true},
		{syncclient.NewRequestError(403, "recovery_session_stale"), false, true},
	} {
		got := recoveryVaultError(tt.err)
		if errors.Is(got, ErrRecoveryEvidence) != tt.evidence || errors.Is(got, syncclient.ErrTrustInvalidated) != tt.invalidated {
			t.Fatal("vault classification changed meaning", got)
		}
	}
}
