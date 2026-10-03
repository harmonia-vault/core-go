package mobileworkflow

import (
	"context"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
	"strconv"
	"testing"
)

func TestMobileDAGTransitionControlledBindingAdvance(t *testing.T) {
	_, _, _, p, _ := b2MobileFixture(t)
	preparation := b2Preparation(t, p)
	x := p.Transition.Submission.Transition
	seq, _ := strconv.ParseUint(x.ExpectedSequence, 10, 64)
	p.AcceptedSequence = seq + 1
	p.Applied = true
	before := syncclient.DAGRecoveryBinding{Profile: cryptox.RecoveryDAGCapability, Endpoint: p.Endpoint, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, Pin: p.Pin, InitializationHash: preparation.InitializationHash, InitializationProposalHash: preparation.InitializationProposalHash, SessionHash: x.SessionHash, ExpiresAt: 1000, RecoveryGeneration: x.OldRecoveryGeneration, RecoveryHeadHash: x.PreviousTransitionHash, RecoverySigningPublicKey: x.OldRecoverySigningPublicKey, RecoveryReceivingPublicKey: x.OldRecoveryReceivingPublicKey, RotationRequired: true, PendingKind: p.Kind, PendingID: p.OperationID, PendingHash: p.ContentHash}
	next := before
	next.RecoveryGeneration = x.NewRecoveryGeneration
	next.RecoveryHeadHash = p.ContentHash
	next.RecoverySigningPublicKey = x.NewRecoverySigningPublicKey
	next.RecoveryReceivingPublicKey = x.NewRecoveryReceivingPublicKey
	next.RotationRequired = false
	if err := confirmDAGOwnerRotation(before, next, p); err != nil {
		t.Fatal("valid durable original advance", err)
	}
	if err := confirmDAGOwnerRotation(next, next, p); err != nil {
		t.Fatal("same applied binding", err)
	}
	for name, edit := range map[string]func(*syncclient.DAGRecoveryBinding){"expiry-extension": func(b *syncclient.DAGRecoveryBinding) { b.ExpiresAt++ }, "session": func(b *syncclient.DAGRecoveryBinding) { b.SessionHash = "different" }, "account": func(b *syncclient.DAGRecoveryBinding) { b.AccountID = "other" }, "endpoint": func(b *syncclient.DAGRecoveryBinding) { b.Endpoint = "https://other.invalid" }, "pin": func(b *syncclient.DAGRecoveryBinding) { b.Pin.DeviceID = "other" }, "initialization": func(b *syncclient.DAGRecoveryBinding) { b.InitializationHash = "different" }, "head": func(b *syncclient.DAGRecoveryBinding) { b.RecoveryHeadHash = "different" }, "signing": func(b *syncclient.DAGRecoveryBinding) { b.RecoverySigningPublicKey = before.RecoverySigningPublicKey }, "receiving": func(b *syncclient.DAGRecoveryBinding) {
		b.RecoveryReceivingPublicKey = before.RecoveryReceivingPublicKey
	}, "generation": func(b *syncclient.DAGRecoveryBinding) { b.RecoveryGeneration = "999" }, "pending-id": func(b *syncclient.DAGRecoveryBinding) { b.PendingID = "other" }, "pending-hash": func(b *syncclient.DAGRecoveryBinding) { b.PendingHash = "different" }, "rotation-required": func(b *syncclient.DAGRecoveryBinding) { b.RotationRequired = true }} {
		t.Run(name, func(t *testing.T) {
			bad := next
			edit(&bad)
			if confirmDAGOwnerRotation(before, bad, p) == nil {
				t.Fatal("uncontrolled binding advancement")
			}
		})
	}
	for name, edit := range map[string]func(*syncclient.ProtectedDAGOperation){"not-applied": func(p *syncclient.ProtectedDAGOperation) { p.Applied = false }, "not-accepted": func(p *syncclient.ProtectedDAGOperation) { p.AcceptedSequence = 0 }, "wrong-sequence": func(p *syncclient.ProtectedDAGOperation) { p.AcceptedSequence++ }, "original-session": func(p *syncclient.ProtectedDAGOperation) {
		p.Transition.Submission.Transition.SessionHash = "different"
	}, "original-new-key": func(p *syncclient.ProtectedDAGOperation) {
		p.Transition.Submission.Transition.NewRecoverySigningPublicKey = "different"
	}} {
		t.Run(name, func(t *testing.T) {
			bad := clone(p)
			edit(&bad)
			if confirmDAGOwnerRotation(before, next, bad) == nil || confirmDAGOwnerRotation(next, next, bad) == nil {
				t.Fatal("unconfirmed packet authorized first/repeated advance")
			}
		})
	}
}

func TestMobileDAGTransitionRetryableErrorClassification(t *testing.T) {
	for name, tc := range map[string]struct {
		action string
		err    error
		want   bool
	}{
		"transport":           {"retry", errors.Join(syncclient.ErrEnrollmentPending, syncclient.ErrDAGRequestUnavailable), true},
		"challenge-transport": {"begin", errors.Join(syncclient.ErrDAGPreparationPending, syncclient.ErrDAGRequestUnavailable), true},
		"504":                 {"retry", errors.Join(syncclient.ErrEnrollmentPending, syncclient.NewRequestError(504, "")), true},
		"408":                 {"retry", errors.Join(syncclient.ErrEnrollmentPending, syncclient.NewRequestError(408, "")), true},
		"429":                 {"retry", errors.Join(syncclient.ErrEnrollmentPending, syncclient.NewRequestError(429, "")), true},
		"409-conflict":        {"retry", errors.Join(syncclient.ErrEnrollmentPending, syncclient.NewRequestError(409, "")), false},
		"401":                 {"begin", errors.Join(syncclient.ErrDAGPreparationPending, syncclient.NewRequestError(401, "")), false},
		"wire":                {"retry", errors.Join(syncclient.ErrEnrollmentPending, cryptox.ErrInvalidWire), false},
		"protocol":            {"retry", errors.Join(syncclient.ErrEnrollmentPending, errors.New("protocol major2 mismatch")), false},
		"cancel":              {"begin", errors.Join(syncclient.ErrDAGPreparationPending, syncclient.ErrDAGRequestUnavailable, context.Canceled), false},
		"wrong-code":          {"seal", syncclient.ErrDAGNewCodeMismatch, true},
		"already-prepared":    {"begin", ErrDAGCodeAlreadyPrepared, true},
		"readonly-never-soft": {"info", errors.Join(syncclient.ErrEnrollmentPending, syncclient.ErrDAGRequestUnavailable), false},
		"wrong-stage":         {"begin", syncclient.ErrDAGNewCodeMismatch, false},
	} {
		t.Run(name, func(t *testing.T) {
			if dagTransitionRetryable(tc.action, tc.err) != tc.want {
				t.Fatal("wrong error retained or prematurely retired original owner")
			}
		})
	}
}
