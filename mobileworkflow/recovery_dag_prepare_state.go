package mobileworkflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrDAGPreparationInterrupted = errors.New("original DAG preparation requires its live owner; preserve interrupted original ID")

type recoveryDAGPreparationState struct {
	Version            int             `json:"version"`
	Profile            string          `json:"profile"`
	Endpoint           string          `json:"endpoint"`
	AccountID          string          `json:"accountId"`
	AccountGeneration  uint64          `json:"accountGeneration"`
	DeviceID           string          `json:"deviceId"`
	SigningPublicKey   string          `json:"signingPublicKey"`
	ReceivingPublicKey string          `json:"receivingPublicKey"`
	OwnerEpoch         uint64          `json:"ownerEpoch"`
	Record             json.RawMessage `json:"record"`
}
type RecoveryDAGPreparationInfo struct {
	Version            int    `json:"version"`
	Profile            string `json:"profile"`
	State              string `json:"state"`
	OperationID        string `json:"operationId,omitempty"`
	Phase              string `json:"phase,omitempty"`
	NeedsOriginalOwner bool   `json:"needsOriginalOwner"`
	TrustedDevice      bool   `json:"trustedDevice"`
}

func (w *Workflow) validateDAGPreparationLocked(b syncclient.DAGJournalBinding, old *syncclient.ProtectedDAGOperation) error {
	r := w.state.RecoveryDAGPreparation
	if w.state.RecoveryDAGRecoveredPreparation != nil {
		if r != nil {
			return ErrDAGProtectedState
		}
		return w.validateDAGRecoveredPreparationLocked(b, old)
	}
	if r == nil {
		return nil
	}
	if r.Version != 1 || r.Profile != cryptox.RecoveryDAGCapability || r.Endpoint != b.Endpoint || r.AccountID != b.AccountID || r.AccountGeneration != b.AccountGeneration || r.OwnerEpoch != b.OwnerEpoch || r.DeviceID != w.state.DeviceID || r.SigningPublicKey != w.state.SigningPublicKey || r.ReceivingPublicKey != w.state.ReceivingPublicKey {
		return ErrDAGProtectedState
	}
	p, err := syncclient.DecodeDAGTransitionPreparation(r.Record)
	if err != nil {
		return err
	}
	return validateDAGPreparationContext(b, p, old)
}
func validateDAGPreparationContext(b syncclient.DAGJournalBinding, p syncclient.DAGTransitionPreparation, old *syncclient.ProtectedDAGOperation) error {
	if p.Endpoint != b.Endpoint || p.AccountID != b.AccountID || p.AccountGeneration != b.AccountGeneration {
		return ErrDAGProtectedState
	}
	if old == nil {
		if p.PriorOperationID != "" || p.PriorContentHash != "" || p.PriorAcceptedSequence != 0 {
			return ErrDAGProtectedState
		}
	} else if !old.Applied || old.AcceptedSequence == 0 || p.Pin != old.Pin || p.PriorOperationID != old.OperationID || p.PriorContentHash != old.ContentHash || p.PriorAcceptedSequence != old.AcceptedSequence {
		return ErrDAGProtectedState
	}
	if old != nil {
		if old.Kind != "transition-v2" || old.Transition == nil {
			return ErrDAGProtectedState
		}
		t := old.Transition.Submission.Transition
		if p.PreviousTransitionHash != old.ContentHash || p.OldRecoveryGeneration != t.NewRecoveryGeneration || p.OldRecoverySigningPublicKey != t.NewRecoverySigningPublicKey || p.OldRecoveryReceivingPublicKey != t.NewRecoveryReceivingPublicKey {
			return ErrDAGProtectedState
		}
	}
	return nil
}
func (s mobileDAGStore) LoadTransitionPreparation() (syncclient.DAGTransitionPreparation, error) {
	w := s.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := s.ownerLocked(s.binding); err != nil {
		return syncclient.DAGTransitionPreparation{}, err
	}
	if w.state.RecoveryDAGPreparation == nil {
		return syncclient.DAGTransitionPreparation{}, os.ErrNotExist
	}
	return syncclient.DecodeDAGTransitionPreparation(w.state.RecoveryDAGPreparation.Record)
}
func (s mobileDAGStore) SaveTransitionPreparation(p syncclient.DAGTransitionPreparation) error {
	w := s.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := s.ownerLocked(s.binding); err != nil {
		return err
	}
	if w.state.RecoveryDAGRecoveredPreparation != nil {
		return ErrDAGProtectedState
	}
	if err := syncclient.ValidateDAGTransitionPreparation(p); err != nil {
		return err
	}
	var old *syncclient.ProtectedDAGOperation
	if w.state.RecoveryDAG != nil {
		value, err := syncclient.DecodeDAGJournal(s.binding, w.state.RecoveryDAG.Journal)
		if err != nil {
			return err
		}
		old = &value
	}
	if err := validateDAGPreparationContext(s.binding, p, old); err != nil {
		return err
	}
	if stored := w.state.RecoveryDAGPreparation; stored == nil {
		if p.Phase != "intent" {
			return ErrDAGProtectedState
		}
	} else {
		before, err := syncclient.DecodeDAGTransitionPreparation(stored.Record)
		if err != nil {
			return err
		}
		if !syncclient.DAGPreparationSameIntent(before, p) {
			return syncclient.ErrDAGPreparationConflict
		}
		if before.Phase == "prepared" && !samePreparation(before, p) {
			return syncclient.ErrDAGPreparationConflict
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	candidate := clone(w.state)
	candidate.Cloud = w.engine.State()
	b := s.binding
	candidate.RecoveryDAGPreparation = &recoveryDAGPreparationState{Version: 1, Profile: cryptox.RecoveryDAGCapability, Endpoint: b.Endpoint, AccountID: b.AccountID, AccountGeneration: b.AccountGeneration, DeviceID: s.deviceID, SigningPublicKey: s.signingPublicKey, ReceivingPublicKey: s.receivingPublicKey, OwnerEpoch: b.OwnerEpoch, Record: raw}
	return w.saveDAGCandidateLocked(candidate)
}
func samePreparation(a, b syncclient.DAGTransitionPreparation) bool {
	x, ex := json.Marshal(a)
	y, ey := json.Marshal(b)
	return ex == nil && ey == nil && bytes.Equal(x, y)
}
func (w *Workflow) saveDAGCandidateLocked(candidate protectedState) error {
	w.requiresDAGCAS = true
	candidate.DAGCASRequired = true
	if w.dagPersistenceFailed {
		return ErrDAGPersistence
	}
	if w.saveNativeCAS == nil || w.checkNativeState == nil {
		return ErrDAGAtomicStoreRequired
	}
	if err := w.checkNativeState(w.protectedSHA256); err != nil {
		w.failDAGPersistenceLocked()
		return errors.Join(ErrDAGPersistence, err)
	}
	if r := candidate.RecoveryDAGResolution; r != nil {
		r.OwnerEpoch = candidate.Cloud.SessionEpoch
	}
	if e := validateDAGResolutionAdvance(w.state, candidate); e != nil {
		return e
	}
	encoded, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if len(encoded) > 8<<20 {
		w.failDAGPersistenceLocked()
		return ErrDAGProtectedState
	}
	if err = w.saveNativeCAS(w.protectedSHA256, encoded); err != nil {
		w.failDAGPersistenceLocked()
		return errors.Join(ErrDAGPersistence, err)
	}
	w.state = candidate
	w.protectedSHA256 = protectedStateHash(encoded)
	return nil
}
func (w *Workflow) newDAGPreparationStore() (mobileDAGStore, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, err := w.dagBindingLocked()
	if err != nil {
		return mobileDAGStore{}, err
	}
	return mobileDAGStore{workflow: w, binding: b, deviceID: w.state.DeviceID, signingPublicKey: w.state.SigningPublicKey, receivingPublicKey: w.state.ReceivingPublicKey}, nil
}
func (w *Workflow) RecoveryDAGPreparationInfo() (RecoveryDAGPreparationInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := RecoveryDAGPreparationInfo{Version: 1, Profile: cryptox.RecoveryDAGCapability, State: "none"}
	if w.closed {
		return out, ErrClosed
	}
	if w.dagPersistenceFailed {
		return out, ErrDAGPersistence
	}
	if w.state.RecoveryDAGRecoveredPreparation != nil {
		return out, ErrDAGPreparationInterrupted
	}
	if w.state.RecoveryDAGPreparation == nil {
		return out, nil
	}
	if err := w.validateDAGStateLocked(); err != nil {
		return out, err
	}
	p, err := syncclient.DecodeDAGTransitionPreparation(w.state.RecoveryDAGPreparation.Record)
	if err != nil {
		return out, err
	}
	out.State = "preparation-pending"
	out.OperationID = p.OperationID
	out.Phase = p.Phase
	out.NeedsOriginalOwner = true
	return out, nil
}
