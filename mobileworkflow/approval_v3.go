package mobileworkflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/pairing"
	"github.com/harmonia-vault/core-go/syncclient"
)

type approvalRecordV3 struct {
	Version             int                          `json:"version"`
	SessionEpoch        uint64                       `json:"sessionEpoch"`
	PairingID           string                       `json:"pairingId"`
	ChoicesHash         string                       `json:"choicesHash"`
	CreatedAt           int64                        `json:"createdAt"`
	LastObservedAt      int64                        `json:"lastObservedAt"`
	DeadlineClosed      bool                         `json:"deadlineClosed,omitempty"`
	Attempted           bool                         `json:"attempted"`
	Approval            cryptox.EnrollmentApprovalV3 `json:"approval"`
	Sequence            uint64                       `json:"sequence,omitempty"`
	CompletionSignature string                       `json:"completionSignature,omitempty"`
}

func approvalSelectionsV3(r *approvalRecordV3) []ApprovalSelection {
	out := make([]ApprovalSelection, 0, len(r.Approval.Grants))
	for _, s := range r.Approval.Grants {
		g := s.Grant
		out = append(out, ApprovalSelection{g.EnvironmentID, g.Role, g.ExpiresAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnvironmentID < out[j].EnvironmentID })
	return out
}
func (w *Workflow) validateApprovalV3(r *approvalRecordV3) error {
	if r == nil {
		return nil
	}
	if w.state.Root == nil || w.state.Cloud.AccountClosed || r.Version != 1 || r.SessionEpoch != w.engine.State().SessionEpoch || r.CreatedAt <= 0 || r.LastObservedAt < r.CreatedAt || r.Approval.InitiatorSignature != "" || r.Approval.Context.ApproverDeviceID != w.state.DeviceID || r.Approval.Context.ApproverSigningPublicKey != w.state.SigningPublicKey || r.Approval.Context.ApproverReceivingPublicKey != w.state.ReceivingPublicKey || r.Approval.Context.AccountID != w.state.AccountID || r.Approval.Context.AccountGeneration != w.state.AccountGeneration {
		return errors.New("protected v3 approval manager/account/epoch invalid")
	}
	expires, err := strconv.ParseInt(r.Approval.Context.ExpiresAt, 10, 64)
	if err != nil || r.CreatedAt >= expires || expires-r.CreatedAt > 120 || r.CreatedAt > w.now().Unix()+5 {
		return errors.New("protected v3 approval deadline invalid")
	}
	h, err := choicesHash(r.PairingID, approvalSelectionsV3(r))
	if err != nil || h != r.ChoicesHash {
		return errors.New("protected v3 approval explicit choices changed")
	}
	raw, err := json.Marshal(r.Approval)
	if err != nil {
		return err
	}
	if _, err = cryptox.DecodeEnrollmentApprovalV3(raw); err != nil {
		return err
	}
	pin, initial, err := w.originPinAndInitial()
	if err != nil {
		return err
	}
	if _, err = cryptox.VerifyIssuerEvidenceV2(pin, r.Approval.IssuerProof, initial...); err != nil {
		return err
	}
	anchor := cryptox.ConfirmedEnrollmentAnchor{Context: r.Approval.Context, TranscriptHash: r.Approval.TranscriptHash}
	if _, err = cryptox.VerifyHistoricalEnrollmentApprovalV3(anchor, r.Approval); err != nil {
		return err
	}
	if r.Sequence != 0 {
		if !r.Attempted || r.Sequence > 9007199254740991 || r.CompletionSignature == "" {
			return errors.New("protected v3 approval completion invalid")
		}
		a := r.Approval
		a.InitiatorSignature = r.CompletionSignature
		if _, err = cryptox.VerifyCompletedEnrollmentV3(anchor, a); err != nil {
			return err
		}
	} else if r.CompletionSignature != "" {
		return errors.New("v3 approval completion signature lacks accepted sequence")
	}
	return nil
}
func (w *Workflow) observeApprovalV3(r *approvalRecordV3) error {
	now := w.now().Unix()
	if now < r.LastObservedAt-5 {
		return pairing.ErrExpired
	}
	changed := false
	if now > r.LastObservedAt {
		r.LastObservedAt = now
		changed = true
	}
	expiry, _ := strconv.ParseInt(r.Approval.Context.ExpiresAt, 10, 64)
	if !r.DeadlineClosed && now >= expiry {
		r.DeadlineClosed = true
		changed = true
	}
	if changed {
		return w.persist()
	}
	return nil
}
func (w *Workflow) ApprovalInfoV3() (ApprovalInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ApprovalInfo{}, ErrClosed
	}
	if len(w.state.SelfRevocation) > 0 {
		return ApprovalInfo{}, ErrSelfRevocationPending
	}
	if w.state.Recovery != nil {
		return ApprovalInfo{}, ErrRecoveryRestricted
	}
	if w.enrollmentPending() {
		return ApprovalInfo{}, ErrMobileEnrollmentPending
	}
	r := w.state.PendingApprovalV3
	if r == nil {
		return ApprovalInfo{State: "none"}, nil
	}
	if err := w.validateApprovalV3(r); err != nil {
		return ApprovalInfo{}, err
	}
	if err := w.observeApprovalV3(r); err != nil {
		return ApprovalInfo{}, err
	}
	state := "prepared"
	if r.Attempted {
		state = "unknown"
	}
	if r.Sequence != 0 {
		state = "complete"
	} else if r.DeadlineClosed {
		state = "expired-pending"
	}
	return ApprovalInfo{State: state, PairingID: r.PairingID, DeviceID: r.Approval.Context.InitiatorDeviceID, Selections: approvalSelectionsV3(r), ExpiresAt: r.Approval.Context.ExpiresAt, Sequence: r.Sequence}, nil
}
func (w *Workflow) currentApprovalV3(choices []ApprovalSelection, original *approvalRecordV3) (cryptox.IssuerProofV2, cryptox.PinnedIssuerRoot, []cryptox.SignedGrantWire, error) {
	var p cryptox.IssuerProofV2
	var pin cryptox.PinnedIssuerRoot
	envs := make([]string, 0, len(choices))
	for _, s := range choices {
		envs = append(envs, s.EnvironmentID)
	}
	p, pin, initial, err := w.client.PrepareEnrollmentProofV3(envs)
	if err != nil {
		return p, pin, nil, err
	}
	originalTargets := map[string]string{}
	if original != nil {
		for _, t := range original.Approval.IssuerProof.Targets {
			originalTargets[t.EnvironmentID] = t.AuthorityHash
		}
	}
	currentTargets := map[string]string{}
	for _, t := range p.Targets {
		currentTargets[t.EnvironmentID] = t.AuthorityHash
	}
	for _, s := range choices {
		g, err := w.grant(s.EnvironmentID)
		if err != nil || g.Role != "admin" {
			return p, pin, nil, localstate.ErrUnauthorized
		}
		child, _ := strconv.ParseUint(s.ExpiresAt, 10, 64)
		parent, _ := strconv.ParseUint(g.ExpiresAt, 10, 64)
		if child != 0 && child <= uint64(w.now().Unix()) || parent != 0 && (child == 0 || child > parent) {
			return p, pin, nil, localstate.ErrUnauthorized
		}
		if original != nil && (originalTargets[s.EnvironmentID] == "" || originalTargets[s.EnvironmentID] != currentTargets[s.EnvironmentID]) {
			return p, pin, nil, ErrApprovalEvidence
		}
	}
	return p, pin, initial, nil
}
func (w *Workflow) approvalResultV3(r *approvalRecordV3, state string) ApprovalResult {
	return ApprovalResult{State: state, PairingID: r.PairingID, DeviceID: r.Approval.Context.InitiatorDeviceID, Sequence: r.Sequence}
}
func (w *Workflow) acceptApprovalV3(r *approvalRecordV3, a *syncclient.ApproverV3, s syncclient.PairingStatusV3) (ApprovalResult, error) {
	if err := a.MatchApproval(s, r.Approval); err != nil {
		return w.approvalResultV3(r, "unknown"), errors.Join(ErrApprovalPending, err)
	}
	if s.State != "complete" {
		return w.approvalResultV3(r, "approved"), nil
	}
	oldSeq, oldSig := r.Sequence, r.CompletionSignature
	r.Sequence = *s.Sequence
	r.CompletionSignature = s.Approval.InitiatorSignature
	if err := w.persist(); err != nil {
		r.Sequence = oldSeq
		r.CompletionSignature = oldSig
		return w.approvalResultV3(r, "unknown"), errors.Join(ErrApprovalPending, err)
	}
	return w.approvalResultV3(r, "complete"), nil
}
func (w *Workflow) ApprovePairingV3(ctx context.Context, input ApprovalInput) (ApprovalResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ApprovalResult{}, ErrClosed
	}
	if len(w.state.SelfRevocation) > 0 {
		return ApprovalResult{}, ErrSelfRevocationPending
	}
	if w.state.Recovery != nil {
		return ApprovalResult{}, ErrRecoveryRestricted
	}
	if w.enrollmentPending() {
		return ApprovalResult{}, ErrMobileEnrollmentPending
	}
	if w.state.PendingApproval != nil && w.state.PendingApproval.Sequence == 0 {
		return ApprovalResult{}, ErrApprovalPending
	}
	fingerprint, err := choicesHash(input.PairingID, input.Selections)
	if err != nil {
		return ApprovalResult{}, err
	}
	if old := w.state.PendingApprovalV3; old != nil && old.Sequence == 0 {
		if old.PairingID != input.PairingID || old.ChoicesHash != fingerprint {
			return ApprovalResult{}, syncclient.ErrWriteConflict
		}
		return w.approvalResultV3(old, "unknown"), ErrApprovalPending
	}
	if !pairing.NativeAvailable() {
		return ApprovalResult{}, pairing.ErrUnavailable
	}
	if len(input.ShortCode) != 8 {
		return ApprovalResult{}, pairing.ErrContext
	}
	for _, b := range input.ShortCode {
		if b < '0' || b > '9' {
			return ApprovalResult{}, pairing.ErrContext
		}
	}
	if err = w.refresh(ctx); err != nil {
		return ApprovalResult{}, err
	}
	if _, _, _, err = w.currentApprovalV3(input.Selections, nil); err != nil {
		return ApprovalResult{}, err
	}
	approver, err := w.client.NewApproverV3(input.PairingID, w.signing)
	if err != nil {
		return ApprovalResult{}, err
	}
	defer approver.Close()
	anchor, err := approver.Confirm(ctx, input.ShortCode)
	if err != nil {
		return ApprovalResult{}, err
	}
	if err = w.refresh(ctx); err != nil {
		return ApprovalResult{}, err
	}
	proof, pin, initial, err := w.currentApprovalV3(input.Selections, nil)
	if err != nil {
		return ApprovalResult{}, err
	}
	approval := cryptox.EnrollmentApprovalV3{CertificateVersion: "3", Context: anchor.Context, PairingProfile: pairing.Profile, TranscriptHash: anchor.TranscriptHash, IssuerProof: proof, Grants: []cryptox.SignedGrantWire{}}
	sources := map[string]cryptox.SignedGrantWire{}
	byHash := map[string]cryptox.SignedGrantWire{}
	for _, a := range proof.Authorities {
		h, _ := cryptox.IssuerAuthorityHash(a.Grant)
		byHash[h] = a.Grant
	}
	for _, t := range proof.Targets {
		sources[t.EnvironmentID] = byHash[t.AuthorityHash]
	}
	ordered := append([]ApprovalSelection(nil), input.Selections...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].EnvironmentID < ordered[j].EnvironmentID })
	for i, s := range ordered {
		source := sources[s.EnvironmentID]
		key, err := w.environmentKey(s.EnvironmentID)
		if err != nil {
			return ApprovalResult{}, err
		}
		packet, e := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: s.EnvironmentID, KeyVersion: source.Grant.KeyVersion, RecipientType: "device", RecipientID: anchor.Context.InitiatorDeviceID, RecipientGeneration: "1", RecipientPublicKey: anchor.Context.InitiatorReceivingPublicKey})
		clear(key)
		if e != nil {
			return ApprovalResult{}, e
		}
		sum := sha256.Sum256([]byte(input.PairingID))
		id := "pair3-grant-" + hex.EncodeToString(sum[:16]) + "-" + strconv.Itoa(i)
		g := cryptox.Grant{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, IssuerDeviceID: w.state.DeviceID, SubjectDeviceID: anchor.Context.InitiatorDeviceID, SubjectSigningPublicKey: anchor.Context.InitiatorSigningPublicKey, SubjectReceivingPublicKey: anchor.Context.InitiatorReceivingPublicKey, EnvironmentID: s.EnvironmentID, KeyVersion: source.Grant.KeyVersion, GrantGeneration: "1", Role: s.Role, ExpiresAt: s.ExpiresAt, IdempotencyKey: id, Envelope: cryptox.EncodeBase64(packet)}
		signed, e := cryptox.SignGrant(g, w.signing)
		if e != nil {
			return ApprovalResult{}, e
		}
		approval.Grants = append(approval.Grants, cryptox.GrantToWire(signed))
	}
	approval, err = cryptox.SignEnrollmentApprovalV3(approval, pin, anchor, w.signing, w.now(), initial...)
	if err != nil {
		return ApprovalResult{}, err
	}
	now := w.now().Unix()
	record := &approvalRecordV3{Version: 1, SessionEpoch: w.engine.State().SessionEpoch, PairingID: input.PairingID, ChoicesHash: fingerprint, CreatedAt: now, LastObservedAt: now, Approval: approval}
	w.state.PendingApprovalV3 = record
	if err = w.persist(); err != nil {
		return w.approvalResultV3(record, "unknown"), err
	}
	return w.retryApprovalV3(ctx, record)
}
func (w *Workflow) RetryApprovalV3(ctx context.Context, id string) (ApprovalResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ApprovalResult{}, ErrClosed
	}
	if len(w.state.SelfRevocation) > 0 {
		return ApprovalResult{}, ErrSelfRevocationPending
	}
	if w.state.Recovery != nil {
		return ApprovalResult{}, ErrRecoveryRestricted
	}
	if w.enrollmentPending() {
		return ApprovalResult{}, ErrMobileEnrollmentPending
	}
	if w.state.PendingApproval != nil && w.state.PendingApproval.Sequence == 0 {
		return ApprovalResult{}, ErrApprovalPending
	}
	r := w.state.PendingApprovalV3
	if r == nil || r.PairingID != id {
		return ApprovalResult{}, syncclient.ErrWriteConflict
	}
	return w.retryApprovalV3(ctx, r)
}
func (w *Workflow) retryApprovalV3(ctx context.Context, r *approvalRecordV3) (ApprovalResult, error) {
	unknown := w.approvalResultV3(r, "unknown")
	if err := w.validateApprovalV3(r); err != nil {
		return unknown, err
	}
	if err := w.observeApprovalV3(r); err != nil {
		return unknown, err
	}
	if r.Sequence != 0 {
		return w.approvalResultV3(r, "complete"), nil
	}
	if w.client == nil {
		if err := w.boot(ctx); err != nil {
			return unknown, errors.Join(ErrApprovalPending, err)
		}
	}
	approver, err := w.client.NewApproverV3(r.PairingID, w.signing)
	if err != nil {
		return unknown, err
	}
	defer approver.Close()
	if err = approver.BindProtectedApproval(r.Approval); err != nil {
		return unknown, err
	}
	status, err := approver.Query(ctx)
	var fault *syncclient.RequestError
	if errors.As(err, &fault) && fault.Status == 401 && fault.Code == "unauthorized" {
		if err = w.boot(ctx); err == nil {
			approver.Close()
			approver, err = w.client.NewApproverV3(r.PairingID, w.signing)
			if err == nil {
				defer approver.Close()
				err = approver.BindProtectedApproval(r.Approval)
				if err == nil {
					status, err = approver.Query(ctx)
				}
			}
		}
	}
	if err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			return unknown, errors.Join(err, w.invalidateTrust())
		}
		return unknown, errors.Join(ErrApprovalPending, err)
	}
	if status.Approval != nil {
		return w.acceptApprovalV3(r, approver, status)
	}
	if r.DeadlineClosed {
		return unknown, pairing.ErrExpired
	}
	if err = w.refreshForApproval(ctx); err != nil {
		return unknown, errors.Join(ErrApprovalPending, err)
	}
	if _, _, _, err = w.currentApprovalV3(approvalSelectionsV3(r), r); err != nil {
		return unknown, errors.Join(ErrApprovalPending, err)
	}
	if err = ctx.Err(); err != nil {
		return unknown, err
	}
	r.Attempted = true
	if err = w.persist(); err != nil {
		return unknown, err
	}
	status, err = approver.Submit(ctx, r.Approval)
	if err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			return unknown, errors.Join(err, w.invalidateTrust())
		}
		return unknown, errors.Join(ErrApprovalPending, err)
	}
	return w.acceptApprovalV3(r, approver, status)
}
func (w *Workflow) CancelApprovalV3(id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	if len(w.state.SelfRevocation) > 0 {
		return ErrSelfRevocationPending
	}
	if w.state.Recovery != nil {
		return ErrRecoveryRestricted
	}
	if w.enrollmentPending() {
		return ErrMobileEnrollmentPending
	}
	r := w.state.PendingApprovalV3
	if r == nil || r.PairingID != id {
		return syncclient.ErrWriteConflict
	}
	if r.Attempted || r.Sequence != 0 {
		return ErrApprovalPending
	}
	w.state.PendingApprovalV3 = nil
	if err := w.persist(); err != nil {
		w.state.PendingApprovalV3 = r
		return err
	}
	return nil
}
