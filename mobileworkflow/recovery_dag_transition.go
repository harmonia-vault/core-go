package mobileworkflow

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrDAGCodeAlreadyPrepared = errors.New("new recovery code was already prepared; complete reentry without generating another code")

// 只有明确的暂时传输/服务端错误可保留原 owner；wire/认证/冲突失败不得泛化。
func dagTransitionRetryable(action string, err error) bool {
	if action == "seal" && errors.Is(err, syncclient.ErrDAGNewCodeMismatch) || action == "begin" && errors.Is(err, ErrDAGCodeAlreadyPrepared) {
		return true
	}
	if !(action == "begin" && errors.Is(err, syncclient.ErrDAGPreparationPending) || action == "retry" && errors.Is(err, syncclient.ErrEnrollmentPending)) {
		return false
	}
	if errors.Is(err, cryptox.ErrInvalidWire) || errors.Is(err, syncclient.ErrTrustInvalidated) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, syncclient.ErrDAGRequestUnavailable) {
		return true
	}
	var fault *syncclient.RequestError
	return errors.As(err, &fault) && (fault.Status == 408 || fault.Status == 429 || fault.Status >= 500 && fault.Status <= 599)
}

func sameDAGOwnerIdentity(a, b dagOwnerIdentity) bool { a.Snapshot, b.Snapshot = "", ""; return a == b }
func sameDAGRecoveryIdentity(a, b syncclient.DAGRecoveryBinding) bool {
	a.PendingID, b.PendingID = "", ""
	a.PendingKind, b.PendingKind = "", ""
	a.PendingHash, b.PendingHash = "", ""
	return a == b
}
func preparationBinding(p syncclient.DAGTransitionPreparation, b syncclient.DAGRecoveryBinding) bool {
	return p.Endpoint == b.Endpoint && p.AccountID == b.AccountID && p.AccountGeneration == b.AccountGeneration && p.Pin == b.Pin && p.InitializationHash == b.InitializationHash && p.InitializationProposalHash == b.InitializationProposalHash && p.SessionHash == b.SessionHash && p.OldRecoveryGeneration == b.RecoveryGeneration && p.PreviousTransitionHash == b.RecoveryHeadHash && p.OldRecoverySigningPublicKey == b.RecoverySigningPublicKey && p.OldRecoveryReceivingPublicKey == b.RecoveryReceivingPublicKey
}
func (w *Workflow) dagOwnerSnapshot() (dagOwnerIdentity, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, err := w.dagBindingLocked()
	if err != nil {
		return dagOwnerIdentity{}, err
	}
	if err = w.validateDAGStateLocked(); err != nil {
		return dagOwnerIdentity{}, err
	}
	return dagOwnerIdentity{b, w.state.DeviceID, w.state.SigningPublicKey, w.state.ReceivingPublicKey, w.protectedSHA256}, nil
}

// 换代入口封闭在真实原事务结果后；不是任意 Advance(nextBinding)。
func confirmDAGOwnerRotation(before, next syncclient.DAGRecoveryBinding, p syncclient.ProtectedDAGOperation) error {
	if p.Transition == nil || p.Kind != "transition-v2" || !p.Applied || p.AcceptedSequence == 0 || p.OperationID != before.PendingID || p.ContentHash != before.PendingHash || next.PendingID != p.OperationID || next.PendingHash != p.ContentHash || next.PendingKind != p.Kind {
		return ErrDAGOwnerBinding
	}
	t := p.Transition.Submission.Transition
	expected, parseErr := strconv.ParseUint(t.ExpectedSequence, 10, 64)
	if parseErr != nil || p.AcceptedSequence != expected+1 || t.SessionHash != before.SessionHash || next.RecoveryGeneration != t.NewRecoveryGeneration || next.RecoveryHeadHash != p.ContentHash || next.RecoverySigningPublicKey != t.NewRecoverySigningPublicKey || next.RecoveryReceivingPublicKey != t.NewRecoveryReceivingPublicKey || next.RotationRequired {
		return ErrDAGOwnerBinding
	}
	if before == next && !next.RotationRequired && next.RecoveryHeadHash == p.ContentHash {
		return nil
	}
	normalized := next
	normalized.RecoveryGeneration = before.RecoveryGeneration
	normalized.RecoveryHeadHash = before.RecoveryHeadHash
	normalized.RecoverySigningPublicKey = before.RecoverySigningPublicKey
	normalized.RecoveryReceivingPublicKey = before.RecoveryReceivingPublicKey
	normalized.RotationRequired = before.RotationRequired
	expected, err := strconv.ParseUint(t.ExpectedSequence, 10, 64)
	if err != nil || p.AcceptedSequence != expected+1 || normalized != before || t.SessionHash != before.SessionHash || t.OldRecoveryGeneration != before.RecoveryGeneration || t.PreviousTransitionHash != before.RecoveryHeadHash || t.OldRecoverySigningPublicKey != before.RecoverySigningPublicKey || t.OldRecoveryReceivingPublicKey != before.RecoveryReceivingPublicKey || next.RecoveryGeneration != t.NewRecoveryGeneration || next.RecoveryHeadHash != p.ContentHash || next.RecoverySigningPublicKey != t.NewRecoverySigningPublicKey || next.RecoveryReceivingPublicKey != t.NewRecoveryReceivingPublicKey || next.RotationRequired {
		return ErrDAGOwnerBinding
	}
	return nil
}

// action 仅由下面三个 typed Go 方法给出；不接 native/UI 自由命令。
func (w *Workflow) runDAGTransition(parent context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, action string, input []byte) (code string, info syncclient.DAGRecoveryInfo, pending RecoveryDAGPendingInfo, err error) {
	info.RotationRequired = true
	if r == nil {
		return "", info, pending, ErrDAGOwnerMissing
	}
	e, ctx, err := r.acquire(parent, scope, false)
	if err != nil {
		return "", info, pending, err
	}
	var target *dagOwnerTarget
	attached, soft := false, false
	defer func() {
		operationErr := err
		if target != nil {
			if detachErr := e.port.detach(target); detachErr != nil {
				err = errors.Join(err, detachErr)
				soft = false
			}
		}
		if attached {
			w.detachDAGOwner()
		}
		if soft {
			err = errors.Join(operationErr, r.finish(e, ctx, nil))
		} else {
			err = r.finish(e, ctx, err)
		}
		if err != nil {
			code = ""
			info = syncclient.DAGRecoveryInfo{RotationRequired: true}
			pending = RecoveryDAGPendingInfo{}
		}
	}()
	identity, err := w.attachDAGOwnerState(e.invalidate, true)
	if err != nil {
		return "", info, pending, err
	}
	attached = true
	if identity != e.identity {
		return "", info, pending, ErrDAGOwnerBinding
	}
	journal, err := w.newRecoveryDAGJournal()
	if err != nil {
		return "", info, pending, err
	}
	preparation, err := w.newDAGPreparationStore()
	if err != nil {
		return "", info, pending, err
	}
	target = &dagOwnerTarget{entry: e, ctx: ctx, journal: journal, preparation: preparation}
	if err = e.port.attach(target); err != nil {
		target = nil
		return "", info, pending, err
	}
	session, ok := e.session.(*syncclient.DAGRecoverySession)
	if !ok {
		return "", info, pending, ErrDAGOwnerBinding
	}
	before, err := session.VerifiedBinding()
	if err != nil || before != e.binding {
		return "", info, pending, errors.Join(ErrDAGOwnerBinding, err)
	}
	prepared, prepErr := e.port.LoadTransitionPreparation()
	if prepErr != nil && !errors.Is(prepErr, os.ErrNotExist) {
		return "", info, pending, prepErr
	}
	var original syncclient.ProtectedDAGOperation
	if action == "retry" {
		original, err = e.port.Load()
		if err != nil {
			return "", info, pending, err
		}
	}
	switch action {
	case "begin":
		if prepErr == nil && prepared.Phase == "prepared" {
			err = ErrDAGCodeAlreadyPrepared
			break
		}
		if e.phase != "" && e.phase != "intent" && e.phase != "rotated" {
			return "", info, pending, ErrDAGOwnerBinding
		}
		id := prepared.OperationID
		if errors.Is(prepErr, os.ErrNotExist) {
			id, err = randomID()
			if err != nil {
				return "", info, pending, err
			}
			id = "dag-transition-" + strings.TrimPrefix(id, "env-")
		}
		code, err = session.BeginTransition(ctx, id)
	case "seal":
		if prepErr != nil || prepared.Phase != "prepared" || e.phase != "prepared" {
			return "", info, pending, ErrDAGOwnerBinding
		}
		_, err = session.SealTransition(ctx, string(input))
	case "retry":
		if prepErr == nil || e.phase != "sealed" && e.phase != "rotated" {
			return "", info, pending, ErrDAGOwnerBinding
		}
		info, err = session.RetryTransition(ctx)
	default:
		return "", info, pending, ErrDAGOwnerBinding
	}
	operationErr := err
	allowedSoft := dagTransitionRetryable(action, err)
	if err != nil && !allowedSoft {
		return "", info, pending, err
	}
	if e.retired.Load() || ctx.Err() != nil {
		return "", info, pending, errors.Join(operationErr, ErrDAGOwnerMissing, ctx.Err())
	}
	after, checkErr := session.VerifiedBinding()
	if checkErr != nil {
		return "", info, pending, errors.Join(operationErr, checkErr)
	}
	nextIdentity, checkErr := w.dagOwnerSnapshot()
	if checkErr != nil || !sameDAGOwnerIdentity(identity, nextIdentity) {
		return "", info, pending, errors.Join(operationErr, ErrDAGOwnerBinding, checkErr)
	}
	switch action {
	case "begin":
		current, checkErr := e.port.LoadTransitionPreparation()
		if checkErr != nil || !preparationBinding(current, before) || after != before {
			return "", info, pending, errors.Join(operationErr, ErrDAGOwnerBinding, checkErr)
		}
		if operationErr == nil && (current.Phase != "prepared" || code == "") {
			return "", info, pending, ErrDAGOwnerBinding
		}
		if errors.Is(operationErr, syncclient.ErrDAGPreparationPending) && current.Phase != "intent" {
			return "", info, pending, ErrDAGOwnerBinding
		}
		if errors.Is(operationErr, ErrDAGCodeAlreadyPrepared) && current.Phase != "prepared" {
			return "", info, pending, ErrDAGOwnerBinding
		}
		if current.Phase == "prepared" {
			if checkErr = r.pinDeadline(e, current.Challenge.ExpiresAt); checkErr != nil {
				return "", info, pending, checkErr
			}
		}
		e.phase = current.Phase
	case "seal":
		if operationErr != nil {
			current, checkErr := e.port.LoadTransitionPreparation()
			if checkErr != nil || !samePreparation(current, prepared) || after != before {
				return "", info, pending, errors.Join(operationErr, ErrDAGOwnerBinding, checkErr)
			}
		} else {
			sealed, checkErr := e.port.Load()
			if checkErr != nil || syncclient.ValidateDAGPreparationPromotion(prepared, sealed) != nil || !sameDAGRecoveryIdentity(before, after) || after.PendingID != sealed.OperationID || after.PendingHash != sealed.ContentHash || after.PendingKind != sealed.Kind {
				return "", info, pending, errors.Join(ErrDAGOwnerBinding, checkErr)
			}
			if _, checkErr = e.port.LoadTransitionPreparation(); !errors.Is(checkErr, os.ErrNotExist) {
				return "", info, pending, ErrDAGOwnerBinding
			}
			e.phase = "sealed"
		}
	case "retry":
		current, checkErr := e.port.Load()
		if checkErr != nil || !sameDAGQueryOriginal(original, current) {
			return "", info, pending, errors.Join(operationErr, ErrDAGOwnerBinding, checkErr)
		}
		if operationErr == nil {
			if checkErr = confirmDAGOwnerRotation(before, after, current); checkErr != nil {
				return "", info, pending, checkErr
			}
			e.phase = "rotated"
		} else if after != before {
			return "", info, pending, errors.Join(operationErr, ErrDAGOwnerBinding)
		}
	}
	if checkErr = e.port.OwnerAlive(); checkErr != nil {
		return "", info, pending, errors.Join(operationErr, checkErr)
	}
	e.identity = nextIdentity
	e.binding = after
	if operationErr == nil {
		info, err = session.Info()
		if err != nil || info.TrustedDevice || info.RotationRequired != after.RotationRequired {
			return "", info, pending, errors.Join(ErrDAGOwnerBinding, err)
		}
		if action != "begin" {
			pending, err = w.RecoveryDAGPendingInfo()
			if err != nil {
				return "", info, pending, err
			}
		}
	}
	soft = allowedSoft
	return code, info, pending, operationErr
}
func (w *Workflow) BeginDAGRecoveryTransition(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope) (string, error) {
	code, _, _, err := w.runDAGTransition(ctx, r, scope, "begin", nil)
	return code, err
}
func (w *Workflow) SealDAGRecoveryTransition(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, completeNewCode []byte) (RecoveryDAGPendingInfo, error) {
	defer clear(completeNewCode)
	if len(completeNewCode) == 0 || len(completeNewCode) > 512 {
		return RecoveryDAGPendingInfo{}, syncclient.ErrDAGNewCodeMismatch
	}
	seed, decodeErr := cryptox.DecodeRecoveryCode(string(completeNewCode))
	clear(seed)
	if decodeErr != nil {
		return RecoveryDAGPendingInfo{}, syncclient.ErrDAGNewCodeMismatch
	}
	_, _, pending, err := w.runDAGTransition(ctx, r, scope, "seal", completeNewCode)
	return pending, err
}
func (w *Workflow) RetryDAGRecoveryTransition(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope) (syncclient.DAGRecoveryInfo, error) {
	_, info, _, err := w.runDAGTransition(ctx, r, scope, "retry", nil)
	return info, err
}
