package mobileworkflow

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

type DAGRecoveredIntent = syncclient.DAGRecoveredSelectionIntent

type DAGRecoveredChoices struct {
	Version          int                                  `json:"version"`
	Profile          string                               `json:"profile"`
	Sequence         uint64                               `json:"sequence"`
	RecoveryHeadHash string                               `json:"recoveryHeadHash"`
	Environments     []cryptox.RecoveryEnvironmentVersion `json:"environments"`
	TrustedDevice    bool                                 `json:"trustedDevice"`
}

func recoveredPreparationBinding(p syncclient.DAGRecoveredPreparation, b syncclient.DAGRecoveryBinding) bool {
	return !b.RotationRequired && p.Endpoint == b.Endpoint && p.AccountID == b.AccountID && p.AccountGeneration == b.AccountGeneration && p.Pin == b.Pin && p.InitializationHash == b.InitializationHash && p.InitializationProposalHash == b.InitializationProposalHash && p.RestrictedSessionHash == b.SessionHash && p.RecoveryGeneration == b.RecoveryGeneration && p.RecoveryHeadHash == b.RecoveryHeadHash && p.RecoverySigningPublicKey == b.RecoverySigningPublicKey && p.RecoveryReceivingPublicKey == b.RecoveryReceivingPublicKey
}
func recoveredIntentMatches(in DAGRecoveredIntent, p syncclient.ProtectedDAGOperation) bool {
	if p.Kind != "recovered-v2" || p.Recovered == nil {
		return false
	}
	s := p.Recovered.Submission
	rights := append([]cryptox.RecoveredDeviceRight(nil), in.SelectedRights...)
	sort.Slice(rights, func(i, j int) bool { return rights[i].EnvironmentID < rights[j].EnvironmentID })
	return strconv.FormatUint(in.ExpectedSequence, 10) == s.Enrollment.ExpectedSequence && in.RecoveryHeadHash == s.Enrollment.RecoveryTransitionHash && sameJSONValue(rights, s.SelectedRights)
}
func (w *Workflow) runDAGRecovered(parent context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, action string, in DAGRecoveredIntent) (choices DAGRecoveredChoices, info DAGRecoveredInfo, err error) {
	if r == nil {
		return choices, info, ErrDAGOwnerMissing
	}
	e, ctx, err := r.acquire(parent, scope, false)
	if err != nil {
		return choices, info, err
	}
	var target *dagOwnerTarget
	attached, soft := false, false
	defer func() {
		opErr := err
		if target != nil {
			if de := e.port.detach(target); de != nil {
				err = errors.Join(err, de)
				soft = false
			}
		}
		if attached {
			w.detachDAGOwner()
		}
		if soft {
			err = errors.Join(opErr, r.finish(e, ctx, nil))
		} else {
			err = r.finish(e, ctx, err)
		}
		if err != nil {
			choices = DAGRecoveredChoices{}
			info = DAGRecoveredInfo{}
		}
	}()
	identity, err := w.attachDAGOwnerState(e.invalidate, true)
	if err != nil {
		return choices, info, err
	}
	attached = true
	if identity != e.identity {
		return choices, info, ErrDAGOwnerBinding
	}
	if e.phase != "rotated" && e.phase != "device-intent" && e.phase != "device-challenged" && e.phase != "device-sealed" && e.phase != "device-original-applied" {
		return choices, info, ErrDAGOwnerBinding
	}
	journal, err := w.newRecoveryDAGJournal()
	if err != nil {
		return choices, info, err
	}
	store, err := w.newDAGPreparationStore()
	if err != nil {
		return choices, info, err
	}
	target = &dagOwnerTarget{entry: e, ctx: ctx, journal: journal, preparation: store, recoveredPreparation: store}
	if err = e.port.attach(target); err != nil {
		target = nil
		return choices, info, err
	}
	session, ok := e.session.(*syncclient.DAGRecoverySession)
	if !ok {
		return choices, info, ErrDAGOwnerBinding
	}
	before, err := session.VerifiedBinding()
	if err != nil || before != e.binding || before.RotationRequired {
		return choices, info, errors.Join(ErrDAGOwnerBinding, err)
	}
	original, err := e.port.Load()
	if err != nil {
		return choices, info, err
	}
	prepared, prepErr := e.port.LoadRecoveredPreparation()
	if prepErr != nil && !errors.Is(prepErr, os.ErrNotExist) {
		return choices, info, prepErr
	}
	if prepErr == nil && !recoveredPreparationBinding(prepared, before) {
		return choices, info, ErrDAGOwnerBinding
	}
	switch action {
	case "choices":
		if e.phase != "rotated" || prepErr == nil {
			return choices, info, ErrDAGOwnerBinding
		}
		c, ce := session.RecoveredDeviceChoices(ctx)
		err = ce
		choices = DAGRecoveredChoices{Version: 1, Profile: cryptox.RecoveryDAGCapability, Sequence: c.Sequence, RecoveryHeadHash: c.RecoveryHeadHash, Environments: c.Environments}
	case "seal":
		if original.Kind == "recovered-v2" {
			if prepErr == nil || !recoveredIntentMatches(in, original) {
				return choices, info, syncclient.ErrDAGPreparationConflict
			}
			break
		}
		if original.Kind != "transition-v2" || !original.Applied || original.AcceptedSequence == 0 {
			return choices, info, ErrDAGOwnerBinding
		}
		id := prepared.OperationID
		if errors.Is(prepErr, os.ErrNotExist) {
			id, err = randomID()
			if err != nil {
				return choices, info, err
			}
			id = "dag-device-" + strings.TrimPrefix(id, "env-")
		}
		// 私钥副本只属于这次认证lease，registry/session不保留设备私钥。
		w.mu.Lock()
		signing, receiving := bytes.Clone(w.signing), bytes.Clone(w.receiving)
		w.mu.Unlock()
		_, err = session.SealRecoveredDeviceForIntent(ctx, id, identity.DeviceID, signing, receiving, in)
		clear(signing)
		clear(receiving)
	case "retry":
		if prepErr == nil || original.Kind != "recovered-v2" || e.phase != "device-sealed" && e.phase != "device-original-applied" {
			return choices, info, ErrDAGOwnerBinding
		}
		_, err = session.RetryRecoveredDevice(ctx)
	default:
		return choices, info, ErrDAGOwnerBinding
	}
	operationErr := err
	allowedSoft := action == "seal" && dagTransitionRetryable("begin", err) || action == "retry" && dagTransitionRetryable("retry", err)
	if err != nil && !allowedSoft {
		return choices, info, err
	}
	if e.retired.Load() || ctx.Err() != nil {
		return choices, info, errors.Join(operationErr, ErrDAGOwnerMissing, ctx.Err())
	}
	after, checkErr := session.VerifiedBinding()
	if checkErr != nil {
		return choices, info, errors.Join(operationErr, checkErr)
	}
	nextIdentity, checkErr := w.dagOwnerSnapshot()
	if checkErr != nil || !sameDAGOwnerIdentity(identity, nextIdentity) {
		return choices, info, errors.Join(operationErr, ErrDAGOwnerBinding, checkErr)
	}
	switch action {
	case "choices":
		if after != before || nextIdentity != identity {
			return choices, info, ErrDAGOwnerBinding
		}
	case "seal":
		if operationErr != nil {
			p, ce := e.port.LoadRecoveredPreparation()
			if ce != nil || !recoveredPreparationBinding(p, before) || after != before || p.Phase != "intent" {
				return choices, info, errors.Join(operationErr, ErrDAGOwnerBinding, ce)
			}
			e.phase = "device-intent"
		} else {
			current, ce := e.port.Load()
			if ce != nil || current.Kind != "recovered-v2" || !recoveredIntentMatches(in, current) || !sameDAGRecoveryIdentity(before, after) || after.PendingID != current.OperationID || after.PendingHash != current.ContentHash || after.PendingKind != current.Kind {
				return choices, info, errors.Join(ErrDAGOwnerBinding, ce)
			}
			if _, ce = e.port.LoadRecoveredPreparation(); !errors.Is(ce, os.ErrNotExist) {
				return choices, info, ErrDAGOwnerBinding
			}
			if original.Kind == "recovered-v2" {
				if !sameDAGQueryOriginal(original, current) {
					return choices, info, ErrDAGOwnerBinding
				}
			} else {
				expires, pe := strconv.ParseInt(current.Recovered.Submission.Enrollment.ExpiresAt, 10, 64)
				if pe != nil {
					return choices, info, pe
				}
				if ce = r.pinDeadline(e, expires); ce != nil {
					return choices, info, ce
				}
				e.phase = "device-sealed"
			}
		}
	case "retry":
		current, ce := e.port.Load()
		if ce != nil || !sameDAGQueryOriginal(original, current) || after != before {
			return choices, info, errors.Join(operationErr, ErrDAGOwnerBinding, ce)
		}
		if operationErr == nil {
			if !current.Applied || current.AcceptedSequence == 0 {
				return choices, info, ErrDAGOwnerBinding
			}
			e.phase = "device-original-applied"
		}
	}
	if checkErr = e.port.OwnerAlive(); checkErr != nil {
		return choices, info, errors.Join(operationErr, checkErr)
	}
	e.identity, e.binding = nextIdentity, after
	if operationErr == nil {
		info, err = w.DAGRecoveredDeviceInfo()
		if err != nil || info.TrustedDevice {
			return choices, info, errors.Join(ErrDAGOwnerBinding, err)
		}
	}
	soft = allowedSoft
	return choices, info, operationErr
}
func (w *Workflow) DAGRecoveredEnrollmentChoices(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope) (DAGRecoveredChoices, error) {
	c, _, e := w.runDAGRecovered(ctx, r, scope, "choices", DAGRecoveredIntent{})
	return c, e
}
func (w *Workflow) SealDAGRecoveredDevice(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, in DAGRecoveredIntent) (DAGRecoveredInfo, error) {
	_, v, e := w.runDAGRecovered(ctx, r, scope, "seal", in)
	return v, e
}
func (w *Workflow) RetryDAGRecoveredDevice(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope) (DAGRecoveredInfo, error) {
	_, v, e := w.runDAGRecovered(ctx, r, scope, "retry", DAGRecoveredIntent{})
	return v, e
}
