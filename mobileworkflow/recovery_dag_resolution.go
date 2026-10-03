package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
	"strconv"
	"time"
)

// 仅业务metadata；任何终态/原包确认都不授设备可信。
type RecoveryDAGResolutionResult struct {
	Version          int    `json:"version"`
	Profile          string `json:"profile"`
	OperationID      string `json:"operationId,omitempty"`
	TargetHash       string `json:"targetHash,omitempty"`
	Observation      string `json:"observation"`
	LocalState       string `json:"localState"`
	Confirmation     string `json:"confirmation"`
	Sequence         uint64 `json:"sequence,omitempty"`
	RotationRequired bool   `json:"rotationRequired"`
	TrustedDevice    bool   `json:"trustedDevice"`
}

func emptyResolutionResult() RecoveryDAGResolutionResult {
	return RecoveryDAGResolutionResult{Version: 1, Profile: cryptox.RecoveryOperationClosureCapability, Observation: "unknown", LocalState: "pending", Confirmation: "none", RotationRequired: true}
}
func (w *Workflow) resolutionTargetLocked() (cryptox.RecoveryOperationTarget, *syncclient.ProtectedDAGOperation, error) {
	var target cryptox.RecoveryOperationTarget
	binding, e := w.dagBindingLocked()
	if e != nil {
		return target, nil, e
	}
	if e = w.validateDAGResolutionLocked(); e != nil {
		return target, nil, e
	}
	if w.state.RecoveryDAGPreparation != nil || w.state.RecoveryDAGRecoveredPreparation != nil {
		return target, nil, syncclient.ErrRecoveryResolutionUnsupported
	}
	if j := w.state.RecoveryDAG; j != nil {
		if e = w.validateDAGStateLocked(); e != nil {
			return target, nil, e
		}
		p, e := syncclient.DecodeDAGJournal(binding, j.Journal)
		if e != nil {
			return target, nil, e
		}
		target, e = syncclient.RecoveryOperationTargetFromSealedTransition(binding, j.Journal, w.state.DeviceID, w.state.SigningPublicKey, w.state.ReceivingPublicKey)
		if e != nil {
			return target, nil, e
		}
		return target, &p, nil
	}
	if r := w.state.RecoveryDAGResolution; r != nil && r.Pending == nil && len(r.Closed) > 0 {
		return r.Closed[len(r.Closed)-1].Target, nil, nil
	}
	return target, nil, ErrDAGOriginalRequired
}
func (w *Workflow) RecoveryDAGResolutionInfo() (RecoveryDAGResolutionResult, error) {
	out := emptyResolutionResult()
	w.mu.Lock()
	defer w.mu.Unlock()
	target, p, e := w.resolutionTargetLocked()
	if e != nil {
		return out, e
	}
	h, e := target.Hash()
	if e != nil {
		return out, e
	}
	out.OperationID, out.TargetHash = target.OperationID, h
	if p == nil {
		r := w.state.RecoveryDAGResolution
		out.LocalState, out.Observation, out.Confirmation = "closed", "closed", "native-confirmed"
		out.Sequence = r.Closed[len(r.Closed)-1].Receipt.Sequence
	}
	return out, nil
}
func retireResolutionDAGOwner(r *DAGRecoveryRegistry, scope DAGOwnerScope, identity dagOwnerIdentity, t cryptox.RecoveryOperationTarget) error {
	if r == nil {
		return ErrDAGOwnerMissing
	}
	r.mu.Lock()
	if r.disposed || r.scope != scope || !validDAGOwnerScope(scope) {
		r.mu.Unlock()
		return ErrDAGOwnerBinding
	}
	e := r.current
	if e == nil {
		r.mu.Unlock()
		return nil
	}
	if e.busy {
		r.mu.Unlock()
		return ErrDAGQueryBusy
	}
	if !sameDAGOwnerIdentity(e.identity, identity) || e.binding.PendingID != t.OperationID || e.binding.PendingHash != t.DeclaredContentHash || e.binding.SessionHash != t.OriginalSessionHash {
		r.mu.Unlock()
		return ErrDAGOwnerBinding
	}
	e.retired.Store(true)
	if e.timer != nil {
		e.timer.Stop()
	}
	if e.cancel != nil {
		e.cancel()
	}
	r.mu.Unlock()
	e.closeOwner()
	return nil
}
func checkResolutionRegistry(r *DAGRecoveryRegistry, scope DAGOwnerScope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.disposed || r.scope != scope || !validDAGOwnerScope(scope) {
		return ErrDAGOwnerBinding
	}
	return nil
}
func (w *Workflow) QueryDAGOperationResolution(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, completeCurrentCode []byte) (RecoveryDAGResolutionResult, error) {
	return w.resolveDAGOperation(ctx, r, scope, completeCurrentCode, "", false)
}
func (w *Workflow) CloseDAGOperationOriginal(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, completeCurrentCode []byte, expectedTargetHash string) (RecoveryDAGResolutionResult, error) {
	return w.resolveDAGOperation(ctx, r, scope, completeCurrentCode, expectedTargetHash, true)
}
func (w *Workflow) resolveDAGOperation(parent context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, code []byte, expectedHash string, closeRequested bool) (out RecoveryDAGResolutionResult, err error) {
	out = emptyResolutionResult()
	// native基点失效也可能发生于网络前的检查；失败统一在锁外清进程材料。
	defer func() {
		w.mu.Lock()
		failed := w.dagPersistenceFailed
		w.mu.Unlock()
		if failed {
			w.Close()
		}
	}()
	defer clear(code)
	if parent == nil || parent.Err() != nil || len(code) == 0 || len(code) > 512 || r == nil {
		return out, ErrDAGOwnerBinding
	}
	seed, e := cryptox.DecodeRecoveryCode(string(code))
	clear(seed)
	if e != nil {
		return out, e
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	w.mu.Lock()
	if w.dagQueryCancel != nil || w.dagOwnerCancel != nil || w.dagDeviceCancel != nil {
		w.mu.Unlock()
		return out, ErrDAGQueryBusy
	}
	target, original, e := w.resolutionTargetLocked()
	if e != nil {
		w.mu.Unlock()
		return out, e
	}
	hash, e := target.Hash()
	if e != nil || closeRequested && expectedHash != hash {
		w.mu.Unlock()
		return out, ErrDAGOwnerBinding
	}
	binding, e := w.dagBindingLocked()
	if e != nil {
		w.mu.Unlock()
		return out, e
	}
	identity := dagOwnerIdentity{binding, w.state.DeviceID, w.state.SigningPublicKey, w.state.ReceivingPublicKey, w.protectedSHA256}
	httpClient, now := w.http, w.now
	beforeHash := w.protectedSHA256
	w.dagQueryCancel = cancel
	signing := bytes.Clone(w.signing)
	w.mu.Unlock()
	defer clear(signing)
	defer func() {
		cancel()
		w.mu.Lock()
		w.dagQueryCancel = nil
		w.mu.Unlock()
	}()
	out.OperationID, out.TargetHash = target.OperationID, hash
	if e = retireResolutionDAGOwner(r, scope, identity, target); e != nil {
		return out, e
	}
	if e = checkResolutionRegistry(r, scope); e != nil {
		return out, e
	}
	if e = syncclient.CheckRecoveryOperationClosureCapability(ctx, binding.Endpoint, httpClient); e != nil {
		return out, e
	}
	mode := "query"
	if e = checkResolutionRegistry(r, scope); e != nil {
		return out, e
	}
	w.mu.Lock()
	if ctx.Err() != nil || w.closed || w.protectedSHA256 != beforeHash {
		w.mu.Unlock()
		return out, ErrDAGProtectedState
	}
	current, _, e := w.resolutionTargetLocked()
	if e != nil || !sameResolutionJSON(current, target) {
		w.mu.Unlock()
		return out, ErrDAGProtectedState
	}
	candidate := clone(w.state)
	candidate.Cloud = w.engine.State()
	if original != nil {
		state := candidate.RecoveryDAGResolution
		if state == nil {
			bundle := original.Transition.DependencyBundle
			minSeq := recoveryBundleSequence(bundle)
			state = &recoveryDAGResolutionState{Version: 1, Profile: cryptox.RecoveryOperationClosureCapability, Endpoint: binding.Endpoint, AccountID: binding.AccountID, AccountGeneration: binding.AccountGeneration, DeviceID: identity.DeviceID, SigningPublicKey: identity.Signing, ReceivingPublicKey: identity.Receiving, OwnerEpoch: binding.OwnerEpoch, Baseline: recoveryDAGResolutionBaseline{Pin: original.Pin, DependencyBundle: bundle, MinimumSequence: minSeq}, Closed: []recoveryDAGClosedEntry{}}
			candidate.RecoveryDAGResolution = state
		}
		// 原签包的before前缀可能早于已经确认的接受记录，不能替换更完整的账本。
		bundle := original.Transition.DependencyBundle
		if original.Pin != state.Baseline.Pin {
			w.mu.Unlock()
			return out, ErrDAGProtectedState
		}
		if retainsResolutionRecords(state.Baseline.DependencyBundle.Records, bundle.Records) == nil {
			state.Baseline.DependencyBundle = bundle
		} else if retainsResolutionRecords(bundle.Records, state.Baseline.DependencyBundle.Records) != nil {
			w.mu.Unlock()
			return out, ErrDAGProtectedState
		}
		if n := recoveryBundleSequence(state.Baseline.DependencyBundle); n > state.Baseline.MinimumSequence {
			state.Baseline.MinimumSequence = n
		}
		if state.Pending == nil {
			state.Pending = &recoveryDAGResolutionPlan{Target: target, TargetHash: hash, OriginalPublicDigest: target.DeclaredIntentHash}
		}
		plan := state.Pending
		if !sameResolutionJSON(plan.Target, target) {
			w.mu.Unlock()
			return out, ErrDAGProtectedState
		}
		if closeRequested {
			plan.CloseRequested = true
			if plan.Observation == nil || plan.Observation.State != "closed" {
				mode = "resolve-or-close"
				plan.CloseAttempted = true
			}
		}
		if mode == "resolve-or-close" && len(state.Closed) >= maxLocalDAGClosures {
			w.mu.Unlock()
			return out, ErrDAGProtectedState
		}
		if e = w.saveDAGCandidateLocked(candidate); e != nil {
			w.mu.Unlock()
			return out, e
		}
	}
	checkpoint := clone(w.state).RecoveryDAGResolution
	beforeHash = w.protectedSHA256
	w.mu.Unlock()
	minimumGeneration, _ := strconv.ParseUint(target.Basis.RecoveryGeneration, 10, 64)
	if checkpoint != nil {
		verified, e := cryptox.VerifyRecoveryDependencyBundle(checkpoint.Baseline.Pin, checkpoint.Baseline.DependencyBundle)
		if e != nil {
			return out, e
		}
		head, e := verified.RecoveryCheckpoint()
		if e != nil {
			return out, e
		}
		g, _ := strconv.ParseUint(head.RecoveryGeneration, 10, 64)
		if g > minimumGeneration {
			minimumGeneration = g
		}
	}
	session, e := syncclient.OpenRecoveryOperationResolutionSession(ctx, syncclient.RecoveryOperationResolutionConfig{Endpoint: binding.Endpoint, HTTPClient: httpClient, AccountID: binding.AccountID, AccountGeneration: binding.AccountGeneration, MinimumRecoveryGeneration: minimumGeneration, Now: now}, bytes.Clone(code))
	if e != nil {
		return out, e
	}
	defer session.Close()
	receipt, e := session.Resolve(ctx, target, mode, ed25519.PrivateKey(signing))
	if e != nil {
		return out, e
	}
	out.Observation, out.Sequence = receipt.State, receipt.Sequence
	if e = checkResolutionRegistry(r, scope); e != nil {
		return out, e
	}
	w.mu.Lock()
	if ctx.Err() != nil || w.closed || w.protectedSHA256 != beforeHash {
		w.mu.Unlock()
		return out, ErrDAGProtectedState
	}
	if e = w.checkRecoveredDAGNativeLocked(); e != nil {
		w.mu.Unlock()
		return out, e
	}
	candidate = clone(w.state)
	candidate.Cloud = w.engine.State()
	state := candidate.RecoveryDAGResolution
	if state == nil {
		w.mu.Unlock()
		return out, ErrDAGProtectedState
	}
	if original == nil {
		last := state.Closed[len(state.Closed)-1]
		if receipt.State != "closed" || !sameResolutionJSON(last.Receipt, receipt) {
			w.mu.Unlock()
			return out, ErrDAGProtectedState
		}
		out.LocalState, out.Confirmation = "closed", "native-confirmed"
		w.mu.Unlock()
		return out, nil
	}
	if state.Pending == nil || state.Pending.TargetHash != hash {
		w.mu.Unlock()
		return out, ErrDAGProtectedState
	}
	if original.AcceptedSequence != 0 && (receipt.State != "accepted" || receipt.Sequence != original.AcceptedSequence) {
		w.mu.Unlock()
		return out, ErrDAGProtectedState
	}
	state.Pending.Observation = &receipt
	if receipt.State == "closed" && state.Pending.CloseRequested {
		if receipt.Sequence < state.Baseline.MinimumSequence || len(state.Closed) >= maxLocalDAGClosures {
			w.mu.Unlock()
			return out, ErrDAGProtectedState
		}
		state.Closed = append(state.Closed, recoveryDAGClosedEntry{Target: target, TargetHash: hash, Receipt: receipt, OriginalPublicDigest: target.DeclaredIntentHash, OwnerEpoch: binding.OwnerEpoch})
		state.Baseline.MinimumSequence = receipt.Sequence
		state.Pending = nil
		candidate.RecoveryDAG = nil
	}
	if e = w.saveDAGCandidateLocked(candidate); e != nil {
		w.mu.Unlock()
		return out, e
	}
	beforeHash = w.protectedSHA256
	if receipt.State == "closed" && !w.dagResolutionPending() {
		out.LocalState, out.Confirmation = "closed", "native-confirmed"
		w.mu.Unlock()
		return out, nil
	}
	if receipt.State != "accepted" {
		w.mu.Unlock()
		return out, nil
	}
	config, e := withDAGResolutionHistory(syncclient.DAGRecoveryConfig{Endpoint: binding.Endpoint, HTTPClient: httpClient, AccountID: binding.AccountID, AccountGeneration: binding.AccountGeneration, Now: now}, state)
	w.mu.Unlock()
	if e != nil {
		return out, e
	}
	confirmed, bundle, sequence, e := syncclient.ConfirmRecoveryOperationResolutionAccepted(ctx, config, *original, target, receipt, bytes.Clone(code))
	if e != nil {
		return out, errors.Join(syncclient.ErrAcceptedNotApplied, e)
	}
	if e = checkResolutionRegistry(r, scope); e != nil {
		return out, e
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil || w.closed || w.protectedSHA256 != beforeHash {
		return out, ErrDAGProtectedState
	}
	if e = w.checkRecoveredDAGNativeLocked(); e != nil {
		return out, e
	}
	candidate = clone(w.state)
	candidate.Cloud = w.engine.State()
	state = candidate.RecoveryDAGResolution
	if state == nil || state.Pending == nil || state.Pending.TargetHash != hash || candidate.RecoveryDAG == nil {
		return out, ErrDAGProtectedState
	}
	raw, e := json.Marshal(struct {
		OwnerEpoch uint64                           `json:"ownerEpoch"`
		Operation  syncclient.ProtectedDAGOperation `json:"operation"`
	}{binding.OwnerEpoch, confirmed})
	if e != nil {
		return out, e
	}
	candidate.RecoveryDAG.Journal = raw
	state.Pending = nil
	state.Baseline.DependencyBundle = bundle
	if sequence > state.Baseline.MinimumSequence {
		state.Baseline.MinimumSequence = sequence
	}
	if e = w.saveDAGCandidateLocked(candidate); e != nil {
		return out, errors.Join(syncclient.ErrAcceptedNotApplied, e)
	}
	out.LocalState, out.Confirmation = "accepted-original-confirmed", "original-history-confirmed"
	return out, nil
}
func recoveryBundleSequence(bundle cryptox.RecoveryDependencyBundle) uint64 {
	sequence := uint64(1)
	for _, r := range bundle.Records {
		var n uint64
		switch r.Kind {
		case "transition-v1":
			n = r.TransitionV1.Sequence
		case "transition-v2":
			n = r.TransitionV2.Sequence
		case "recovered-v1":
			n = r.RecoveredV1.Sequence
		case "recovered-v2":
			n = r.RecoveredV2.Sequence
		}
		if n > sequence {
			sequence = n
		}
	}
	return sequence
}

// 显式新owner仍完整vault/HPKE，并保留原pin、全部祖先与closed观察序号。
func (w *Workflow) BeginDAGRecoveryAfterClosure(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, completeCurrentCode []byte) (syncclient.DAGRecoveryInfo, error) {
	defer clear(completeCurrentCode)
	if ctx == nil || ctx.Err() != nil || len(completeCurrentCode) == 0 || len(completeCurrentCode) > 512 {
		return syncclient.DAGRecoveryInfo{RotationRequired: true}, ErrDAGOwnerBinding
	}
	seed, e := cryptox.DecodeRecoveryCode(string(completeCurrentCode))
	clear(seed)
	if e != nil {
		return syncclient.DAGRecoveryInfo{RotationRequired: true}, e
	}
	w.mu.Lock()
	if w.dagResolutionPending() || w.state.RecoveryDAG != nil || w.state.RecoveryDAGResolution == nil || len(w.state.RecoveryDAGResolution.Closed) == 0 {
		w.mu.Unlock()
		return syncclient.DAGRecoveryInfo{RotationRequired: true}, ErrDAGResolutionPending
	}
	e = w.validateDAGResolutionLocked()
	w.mu.Unlock()
	if e != nil {
		return syncclient.DAGRecoveryInfo{RotationRequired: true}, e
	}
	return w.runDAGOwner(ctx, r, scope, true, completeCurrentCode)
}
