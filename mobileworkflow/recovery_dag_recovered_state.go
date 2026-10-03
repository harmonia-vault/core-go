package mobileworkflow

import (
	"encoding/json"
	"os"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

func (w *Workflow) validateDAGRecoveredPreparationLocked(b syncclient.DAGJournalBinding, old *syncclient.ProtectedDAGOperation) error {
	r := w.state.RecoveryDAGRecoveredPreparation
	if r == nil {
		return nil
	}
	if w.state.RecoveryDAGPreparation != nil || r.Version != 1 || r.Profile != cryptox.RecoveryDAGCapability || r.Endpoint != b.Endpoint || r.AccountID != b.AccountID || r.AccountGeneration != b.AccountGeneration || r.OwnerEpoch != b.OwnerEpoch || r.DeviceID != w.state.DeviceID || r.SigningPublicKey != w.state.SigningPublicKey || r.ReceivingPublicKey != w.state.ReceivingPublicKey {
		return ErrDAGProtectedState
	}
	p, e := syncclient.DecodeDAGRecoveredPreparation(r.Record)
	if e != nil {
		return e
	}
	return validateDAGRecoveredContext(b, p, old, w.state.DeviceID, w.state.SigningPublicKey, w.state.ReceivingPublicKey)
}
func validateDAGRecoveredContext(b syncclient.DAGJournalBinding, p syncclient.DAGRecoveredPreparation, old *syncclient.ProtectedDAGOperation, device, signing, receiving string) error {
	if old == nil || old.Kind != "transition-v2" || old.Transition == nil || !old.Applied || old.AcceptedSequence == 0 || p.Endpoint != b.Endpoint || p.AccountID != b.AccountID || p.AccountGeneration != b.AccountGeneration || p.Pin != old.Pin || p.DeviceID != device || p.DeviceSigningPublicKey != signing || p.DeviceReceivingPublicKey != receiving || p.PriorOperationID != old.OperationID || p.PriorContentHash != old.ContentHash || p.PriorAcceptedSequence != old.AcceptedSequence {
		return ErrDAGProtectedState
	}
	t := old.Transition.Submission.Transition
	if p.RestrictedSessionHash != t.SessionHash || p.RecoveryHeadHash != old.ContentHash || p.RecoveryGeneration != t.NewRecoveryGeneration || p.RecoverySigningPublicKey != t.NewRecoverySigningPublicKey || p.RecoveryReceivingPublicKey != t.NewRecoveryReceivingPublicKey {
		return ErrDAGProtectedState
	}
	// 除引用外再核同一个完整已签前驱，不能用碰巧相同ID/序号替代原包。
	found := false
	for _, r := range p.BaseBundle.Records {
		if r.TransitionV2 != nil && r.TransitionV2.Sequence == old.AcceptedSequence && sameJSONValue(r.TransitionV2.Submission, old.Transition.Submission) {
			found = true
		}
	}
	if !found {
		return ErrDAGProtectedState
	}
	return nil
}
func (s mobileDAGStore) LoadRecoveredPreparation() (syncclient.DAGRecoveredPreparation, error) {
	w := s.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := s.ownerLocked(s.binding); e != nil {
		return syncclient.DAGRecoveredPreparation{}, e
	}
	if w.state.RecoveryDAGRecoveredPreparation == nil {
		return syncclient.DAGRecoveredPreparation{}, os.ErrNotExist
	}
	return syncclient.DecodeDAGRecoveredPreparation(w.state.RecoveryDAGRecoveredPreparation.Record)
}
func (s mobileDAGStore) SaveRecoveredPreparation(p syncclient.DAGRecoveredPreparation) error {
	w := s.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := s.ownerLocked(s.binding); e != nil {
		return e
	}
	if w.state.RecoveryDAGPreparation != nil || w.state.RecoveryDAG == nil {
		return ErrDAGProtectedState
	}
	if e := syncclient.ValidateDAGRecoveredPreparation(p); e != nil {
		return e
	}
	old, e := syncclient.DecodeDAGJournal(s.binding, w.state.RecoveryDAG.Journal)
	if e != nil {
		return e
	}
	if e = validateDAGRecoveredContext(s.binding, p, &old, s.deviceID, s.signingPublicKey, s.receivingPublicKey); e != nil {
		return e
	}
	if r := w.state.RecoveryDAGRecoveredPreparation; r == nil {
		if p.Phase != "intent" {
			return ErrDAGProtectedState
		}
	} else {
		before, e := syncclient.DecodeDAGRecoveredPreparation(r.Record)
		if e != nil {
			return e
		}
		if !syncclient.DAGRecoveredPreparationSameIntent(before, p) || before.Phase == "challenged" && !sameJSONValue(before, p) {
			return syncclient.ErrDAGPreparationConflict
		}
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	candidate := clone(w.state)
	candidate.Cloud = w.engine.State()
	b := s.binding
	candidate.RecoveryDAGRecoveredPreparation = &recoveryDAGPreparationState{Version: 1, Profile: cryptox.RecoveryDAGCapability, Endpoint: b.Endpoint, AccountID: b.AccountID, AccountGeneration: b.AccountGeneration, DeviceID: s.deviceID, SigningPublicKey: s.signingPublicKey, ReceivingPublicKey: s.receivingPublicKey, OwnerEpoch: b.OwnerEpoch, Record: raw}
	return w.saveDAGCandidateLocked(candidate)
}

type DAGRecoveredInfo struct {
	Version            int    `json:"version"`
	Profile            string `json:"profile"`
	State              string `json:"state"`
	OperationID        string `json:"operationId,omitempty"`
	Phase              string `json:"phase,omitempty"`
	Acceptance         string `json:"acceptance"`
	AcceptedSequence   uint64 `json:"acceptedSequence,omitempty"`
	OriginalConfirmed  bool   `json:"originalConfirmed"`
	NeedsOriginalOwner bool   `json:"needsOriginalOwner"`
	TrustedDevice      bool   `json:"trustedDevice"`
}

func (w *Workflow) DAGRecoveredDeviceInfo() (DAGRecoveredInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := DAGRecoveredInfo{Version: 1, Profile: cryptox.RecoveryDAGCapability, State: "none", Acceptance: "unknown"}
	if w.closed {
		return out, ErrClosed
	}
	if w.dagPersistenceFailed {
		return out, ErrDAGPersistence
	}
	if e := w.validateDAGStateLocked(); e != nil {
		return out, e
	}
	if r := w.state.RecoveryDAGRecoveredPreparation; r != nil {
		p, e := syncclient.DecodeDAGRecoveredPreparation(r.Record)
		if e != nil {
			return out, e
		}
		out.State, out.OperationID, out.Phase, out.NeedsOriginalOwner = "interrupted-original", p.OperationID, p.Phase, true
		return out, nil
	}
	if r := w.state.RecoveryDAG; r != nil {
		b, e := w.dagBindingLocked()
		if e != nil {
			return out, e
		}
		p, e := syncclient.DecodeDAGJournal(b, r.Journal)
		if e != nil {
			return out, e
		}
		if p.Kind == "recovered-v2" {
			out.State, out.OperationID = "pending-original", p.OperationID
			out.AcceptedSequence, out.OriginalConfirmed = p.AcceptedSequence, p.Applied
			if p.AcceptedSequence != 0 {
				out.State, out.Acceptance = "accepted-not-device-applied", "accepted"
			}
		}
	}
	return out, nil
}
