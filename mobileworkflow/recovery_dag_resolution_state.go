package mobileworkflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
	"strconv"
)

var ErrDAGResolutionPending = errors.New("original recovery resolution pending; preserve original ID")

const maxLocalDAGClosures = 640

type recoveryDAGResolutionBaseline struct {
	Pin              cryptox.PinnedIssuerRoot         `json:"pin"`
	DependencyBundle cryptox.RecoveryDependencyBundle `json:"dependencyBundle"`
	MinimumSequence  uint64                           `json:"minimumSequence"`
}
type recoveryDAGResolutionPlan struct {
	Target               cryptox.RecoveryOperationTarget             `json:"target"`
	TargetHash           string                                      `json:"targetHash"`
	OriginalPublicDigest string                                      `json:"originalPublicDigest"`
	CloseRequested       bool                                        `json:"closeRequested"`
	CloseAttempted       bool                                        `json:"closeAttempted"`
	Observation          *cryptox.RecoveryOperationResolutionReceipt `json:"observation"`
}
type recoveryDAGClosedEntry struct {
	Target               cryptox.RecoveryOperationTarget            `json:"target"`
	TargetHash           string                                     `json:"targetHash"`
	Receipt              cryptox.RecoveryOperationResolutionReceipt `json:"receipt"`
	OriginalPublicDigest string                                     `json:"originalPublicDigest"`
	OwnerEpoch           uint64                                     `json:"ownerEpoch"`
}
type recoveryDAGResolutionState struct {
	Version            int                           `json:"version"`
	Profile            string                        `json:"profile"`
	Endpoint           string                        `json:"endpoint"`
	AccountID          string                        `json:"accountId"`
	AccountGeneration  uint64                        `json:"accountGeneration"`
	DeviceID           string                        `json:"deviceId"`
	SigningPublicKey   string                        `json:"signingPublicKey"`
	ReceivingPublicKey string                        `json:"receivingPublicKey"`
	OwnerEpoch         uint64                        `json:"ownerEpoch"`
	Baseline           recoveryDAGResolutionBaseline `json:"baseline"`
	Pending            *recoveryDAGResolutionPlan    `json:"pending"`
	Closed             []recoveryDAGClosedEntry      `json:"closed"`
}

func exactResolutionJSON(raw []byte, nullable string, names ...string) error {
	var m map[string]json.RawMessage
	if decode(raw, &m) != nil || len(m) != len(names) {
		return ErrDAGProtectedState
	}
	for _, n := range names {
		v, ok := m[n]
		if !ok || n != nullable && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return ErrDAGProtectedState
		}
	}
	return nil
}
func (r *recoveryDAGResolutionState) UnmarshalJSON(raw []byte) error {
	if exactResolutionJSON(raw, "pending", "version", "profile", "endpoint", "accountId", "accountGeneration", "deviceId", "signingPublicKey", "receivingPublicKey", "ownerEpoch", "baseline", "pending", "closed") != nil {
		return ErrDAGProtectedState
	}
	var m map[string]json.RawMessage
	if decode(raw, &m) != nil || exactResolutionJSON(m["baseline"], "", "pin", "dependencyBundle", "minimumSequence") != nil {
		return ErrDAGProtectedState
	}
	type plain recoveryDAGResolutionState
	var p plain
	if decode(raw, &p) != nil {
		return ErrDAGProtectedState
	}
	*r = recoveryDAGResolutionState(p)
	return nil
}
func (r *recoveryDAGResolutionPlan) UnmarshalJSON(raw []byte) error {
	if exactResolutionJSON(raw, "observation", "target", "targetHash", "originalPublicDigest", "closeRequested", "closeAttempted", "observation") != nil {
		return ErrDAGProtectedState
	}
	type plain recoveryDAGResolutionPlan
	var p plain
	if decode(raw, &p) != nil {
		return ErrDAGProtectedState
	}
	*r = recoveryDAGResolutionPlan(p)
	return nil
}
func (r *recoveryDAGClosedEntry) UnmarshalJSON(raw []byte) error {
	if exactResolutionJSON(raw, "", "target", "targetHash", "receipt", "originalPublicDigest", "ownerEpoch") != nil {
		return ErrDAGProtectedState
	}
	type plain recoveryDAGClosedEntry
	var p plain
	if decode(raw, &p) != nil {
		return ErrDAGProtectedState
	}
	*r = recoveryDAGClosedEntry(p)
	return nil
}
func (w *Workflow) dagResolutionPending() bool {
	return w.state.RecoveryDAGResolution != nil && w.state.RecoveryDAGResolution.Pending != nil
}
func resolutionTargetSupported(t cryptox.RecoveryOperationTarget) bool {
	return t.Profile == cryptox.RecoveryDAGCapability && t.Kind == "transition-v2" && t.Stage == "sealed" && t.AuthorizationKind == "old-recovery"
}
func validateDAGResolutionState(s protectedState) error {
	r := s.RecoveryDAGResolution
	if r == nil {
		return nil
	}
	gen, e := strconv.ParseUint(s.AccountGeneration, 10, 64)
	if e != nil || gen == 0 || r.Version != 1 || r.Profile != cryptox.RecoveryOperationClosureCapability || r.Endpoint != s.Endpoint || r.AccountID != s.AccountID || r.AccountGeneration != gen || r.DeviceID != s.DeviceID || r.SigningPublicKey != s.SigningPublicKey || r.ReceivingPublicKey != s.ReceivingPublicKey || r.OwnerEpoch != s.Cloud.SessionEpoch || !s.DAGCASRequired || r.Closed == nil || len(r.Closed) > maxLocalDAGClosures || r.Baseline.MinimumSequence == 0 || r.Baseline.MinimumSequence > 9007199254740991 {
		return ErrDAGProtectedState
	}
	graph, e := cryptox.VerifyRecoveryDependencyBundle(r.Baseline.Pin, r.Baseline.DependencyBundle)
	if e != nil || r.Baseline.Pin.AccountID != r.AccountID || r.Baseline.Pin.AccountGeneration != s.AccountGeneration {
		return ErrDAGProtectedState
	}
	checkpoint, e := graph.RecoveryCheckpoint()
	if e != nil || checkpoint.AcceptedSequence > r.Baseline.MinimumSequence || recoveryBundleSequence(r.Baseline.DependencyBundle) > r.Baseline.MinimumSequence {
		return ErrDAGProtectedState
	}
	seen := map[string]bool{}
	seqs := map[uint64]bool{}
	validateTarget := func(t cryptox.RecoveryOperationTarget, h, d string) error {
		actual, e := t.Hash()
		if e != nil || !resolutionTargetSupported(t) || actual != h || d != t.DeclaredIntentHash || t.AccountID != r.AccountID || t.AccountGeneration != s.AccountGeneration || t.DeviceID != r.DeviceID || t.DeviceSigningPublicKey != r.SigningPublicKey || t.DeviceReceivingPublicKey != r.ReceivingPublicKey {
			return ErrDAGProtectedState
		}
		return nil
	}
	for _, c := range r.Closed {
		if validateTarget(c.Target, c.TargetHash, c.OriginalPublicDigest) != nil || c.Receipt.State != "closed" || c.Receipt.ValidateTarget(c.Target) != nil || c.OwnerEpoch > r.OwnerEpoch || c.Receipt.Sequence > r.Baseline.MinimumSequence || seen[c.Target.OperationID] || seqs[c.Receipt.Sequence] {
			return ErrDAGProtectedState
		}
		seen[c.Target.OperationID] = true
		seqs[c.Receipt.Sequence] = true
	}
	closed := resolutionClosedCheckpoints(r)
	if e = syncclient.ValidateDAGClosedHistory(closed, r.Baseline.DependencyBundle.Records); e != nil {
		return e
	}
	if j := s.RecoveryDAG; j != nil {
		p, e := syncclient.DecodeDAGJournal(syncclient.DAGJournalBinding{Endpoint: j.Endpoint, AccountID: j.AccountID, AccountGeneration: j.AccountGeneration, OwnerEpoch: j.OwnerEpoch}, j.Journal)
		if e != nil || seen[p.OperationID] || p.AcceptedSequence != 0 && seqs[p.AcceptedSequence] {
			return ErrDAGProtectedState
		}
		var records []cryptox.RecoveryDAGRecord
		if p.Transition != nil {
			records = p.Transition.DependencyBundle.Records
		} else if p.Recovered != nil {
			records = p.Recovered.DependencyBundle.Records
		}
		if e = syncclient.ValidateDAGClosedHistory(closed, records); e != nil {
			return e
		}
	}
	if j := s.RecoveryDAGPreparation; j != nil {
		p, e := syncclient.DecodeDAGTransitionPreparation(j.Record)
		if e != nil || seen[p.OperationID] {
			return ErrDAGProtectedState
		}
		if e = syncclient.ValidateDAGClosedHistory(closed, p.BaseBundle.Records); e != nil {
			return e
		}
	}
	if j := s.RecoveryDAGRecoveredPreparation; j != nil {
		p, e := syncclient.DecodeDAGRecoveredPreparation(j.Record)
		if e != nil || seen[p.OperationID] {
			return ErrDAGProtectedState
		}
		if e = syncclient.ValidateDAGClosedHistory(closed, p.BaseBundle.Records); e != nil {
			return e
		}
	}
	if s.Root != nil {
		if s.Cloud.Cloud.Sequence < r.Baseline.MinimumSequence {
			return ErrDAGProtectedState
		}
		evidence, e := cryptox.DecodeIssuerRecoveryDAG(s.Cloud.Cloud.IssuerEvidence)
		if e != nil {
			return e
		}
		if _, e = cryptox.VerifyRecoveryDAGAdvance(graph, evidence); e != nil {
			return e
		}
		if e = retainsResolutionRecords(r.Baseline.DependencyBundle.Records, evidence.Records); e != nil {
			return e
		}
		if e = syncclient.ValidateDAGClosedHistory(closed, evidence.Records); e != nil {
			return e
		}
	}
	if p := r.Pending; p != nil {
		if validateTarget(p.Target, p.TargetHash, p.OriginalPublicDigest) != nil || seen[p.Target.OperationID] || p.CloseAttempted && !p.CloseRequested || s.Root != nil || s.Cloud.AccountClosed || s.RecoveryDAG == nil || s.RecoveryDAGPreparation != nil || s.RecoveryDAGRecoveredPreparation != nil {
			return ErrDAGProtectedState
		}
		j := s.RecoveryDAG
		b := syncclient.DAGJournalBinding{Endpoint: r.Endpoint, AccountID: r.AccountID, AccountGeneration: gen, OwnerEpoch: r.OwnerEpoch}
		expected, e := syncclient.RecoveryOperationTargetFromSealedTransition(b, j.Journal, r.DeviceID, r.SigningPublicKey, r.ReceivingPublicKey)
		if e != nil || !sameResolutionJSON(expected, p.Target) {
			return ErrDAGProtectedState
		}
		original, e := syncclient.DecodeDAGJournal(b, j.Journal)
		if e != nil {
			return e
		}
		if p.Observation != nil && (p.Observation.ValidateTarget(p.Target) != nil || original.AcceptedSequence != 0 && (p.Observation.State != "accepted" || p.Observation.Sequence != original.AcceptedSequence)) {
			return ErrDAGProtectedState
		}
	}
	return nil
}
func sameResolutionJSON(a, b any) bool {
	x, ex := json.Marshal(a)
	y, ey := json.Marshal(b)
	return ex == nil && ey == nil && bytes.Equal(x, y)
}

// 追加终态不能抹祖先、原receipt或控制序号；退出只删除活动原包，closed历史保持。
func validateDAGResolutionAdvance(old, next protectedState) error {
	if e := validateDAGResolutionState(next); e != nil {
		return e
	}
	a, b := old.RecoveryDAGResolution, next.RecoveryDAGResolution
	if a == nil {
		return nil
	}
	if b == nil || b.OwnerEpoch < a.OwnerEpoch || b.Baseline.Pin != a.Baseline.Pin || b.Baseline.MinimumSequence < a.Baseline.MinimumSequence || len(b.Closed) < len(a.Closed) {
		return ErrDAGProtectedState
	}
	if len(a.Closed) > 0 {
		for i, c := range a.Closed {
			if !sameResolutionJSON(c, b.Closed[i]) {
				return ErrDAGProtectedState
			}
		}
	}
	// 公开记录编码+seq逐条保持；head之外的已见分支也不能删。
	after := map[string]cryptox.RecoveryDAGRecord{}
	for _, r := range b.Baseline.DependencyBundle.Records {
		ref, e := r.Reference()
		if e != nil {
			return e
		}
		after[ref.Kind+"/"+ref.ReferenceHash] = r
	}
	for _, r := range a.Baseline.DependencyBundle.Records {
		ref, e := r.Reference()
		if e != nil {
			return e
		}
		v, ok := after[ref.Kind+"/"+ref.ReferenceHash]
		if !ok || !sameResolutionJSON(r, v) {
			return ErrDAGProtectedState
		}
	}
	if p := a.Pending; p != nil {
		if q := b.Pending; q != nil {
			if !sameResolutionJSON(p.Target, q.Target) || p.TargetHash != q.TargetHash || p.OriginalPublicDigest != q.OriginalPublicDigest || p.CloseRequested && !q.CloseRequested || p.CloseAttempted && !q.CloseAttempted {
				return ErrDAGProtectedState
			}
			if p.Observation != nil && p.Observation.State != "pending" && (q.Observation == nil || !sameResolutionJSON(p.Observation, q.Observation)) {
				return ErrDAGProtectedState
			}
		} else if !next.Cloud.AccountClosed {
			closed := false
			for _, c := range b.Closed {
				if c.TargetHash == p.TargetHash && p.CloseRequested && c.Receipt.State == "closed" {
					closed = true
				}
			}
			if !closed {
				if next.RecoveryDAG == nil || p.Observation == nil || p.Observation.State != "accepted" {
					return ErrDAGProtectedState
				}
				j := next.RecoveryDAG
				v, e := syncclient.DecodeDAGJournal(syncclient.DAGJournalBinding{Endpoint: j.Endpoint, AccountID: j.AccountID, AccountGeneration: j.AccountGeneration, OwnerEpoch: j.OwnerEpoch}, j.Journal)
				if e != nil || !v.Applied || v.AcceptedSequence != p.Observation.Sequence || v.ContentHash != p.Observation.ContentHash || v.OperationID != p.Target.OperationID {
					return ErrDAGProtectedState
				}
			}
		}
	}
	// 新业务ID在自己的intent保存屏障即可拒绝；不等到HTTP后才发现。
	for _, entry := range b.Closed {
		if next.RecoveryDAG != nil {
			j := next.RecoveryDAG
			v, e := syncclient.DecodeDAGJournal(syncclient.DAGJournalBinding{Endpoint: j.Endpoint, AccountID: j.AccountID, AccountGeneration: j.AccountGeneration, OwnerEpoch: j.OwnerEpoch}, j.Journal)
			if e != nil || v.OperationID == entry.Target.OperationID {
				return ErrDAGProtectedState
			}
		}
		if next.RecoveryDAGPreparation != nil {
			v, e := syncclient.DecodeDAGTransitionPreparation(next.RecoveryDAGPreparation.Record)
			if e != nil || v.OperationID == entry.Target.OperationID {
				return ErrDAGProtectedState
			}
		}
		if next.RecoveryDAGRecoveredPreparation != nil {
			v, e := syncclient.DecodeDAGRecoveredPreparation(next.RecoveryDAGRecoveredPreparation.Record)
			if e != nil || v.OperationID == entry.Target.OperationID {
				return ErrDAGProtectedState
			}
		}
	}
	return nil
}
func (w *Workflow) validateDAGResolutionLocked() error {
	if w.state.RecoveryDAGResolution == nil {
		return nil
	}
	if e := w.checkRecoveredDAGNativeLocked(); e != nil {
		return e
	}
	candidate := clone(w.state)
	candidate.Cloud = w.engine.State()
	return validateDAGResolutionState(candidate)
}

func retainsResolutionRecords(before, after []cryptox.RecoveryDAGRecord) error {
	rows := map[string]cryptox.RecoveryDAGRecord{}
	for _, r := range after {
		ref, e := r.Reference()
		if e != nil {
			return e
		}
		rows[ref.Kind+"/"+ref.ReferenceHash] = r
	}
	for _, r := range before {
		ref, e := r.Reference()
		if e != nil {
			return e
		}
		v, ok := rows[ref.Kind+"/"+ref.ReferenceHash]
		if !ok || !sameResolutionJSON(r, v) {
			return ErrDAGProtectedState
		}
	}
	return nil
}
