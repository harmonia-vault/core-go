package mobileworkflow

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

// RecoveryDeviceSelection is explicit user intent. No environment or Admin role
// is chosen automatically after proving recovery-code possession.
type RecoveryDeviceSelection struct {
	EnvironmentID string
	Role          string
	ExpiresAt     string
}
type RecoveredDeviceInfo struct {
	State         string `json:"state"`
	ID            string `json:"id,omitempty"`
	Sequence      uint64 `json:"sequence,omitempty"`
	TrustedDevice bool   `json:"trustedDevice"`
}
type recoveredDeviceRecord struct {
	Version                int                                  `json:"version"`
	CreatedAt              int64                                `json:"createdAt"`
	SessionEpoch           uint64                               `json:"sessionEpoch"`
	Pin                    cryptox.PinnedIssuerRoot             `json:"pin"`
	OriginalInitialization cryptox.OriginalInitialization       `json:"originalInitialization"`
	Transitions            []cryptox.AcceptedRecoveryTransition `json:"transitions"`
	Packet                 cryptox.RecoveredDeviceSubmission    `json:"packet"`
	ContentHash            string                               `json:"contentHash"`
	AcceptedSequence       uint64                               `json:"acceptedSequence,omitempty"`
	Applied                bool                                 `json:"applied,omitempty"`
	Evidence               *cryptox.IssuerRecoveryProof         `json:"evidence,omitempty"`
	DeadlineClosed         bool                                 `json:"deadlineClosed,omitempty"`
}
type recoveredDeviceChallenge struct {
	ChallengeID            string                `json:"challengeId"`
	Nonce                  string                `json:"nonce"`
	ExpiresAt              int64                 `json:"expiresAt"`
	RestrictedSessionHash  string                `json:"restrictedSessionHash"`
	ExpectedSequence       string                `json:"expectedSequence"`
	RecoveryGeneration     string                `json:"recoveryGeneration"`
	RecoveryTransitionHash string                `json:"recoveryTransitionHash"`
	IssuerEvidence         cryptox.IssuerProofV2 `json:"issuerEvidence"`
}

func (w *Workflow) recoveredDeviceInfo() RecoveredDeviceInfo {
	r := w.state.RecoveredDevice
	if r == nil {
		return RecoveredDeviceInfo{State: "none"}
	}
	out := RecoveredDeviceInfo{State: "pending", ID: r.Packet.Enrollment.OperationID, Sequence: r.AcceptedSequence, TrustedDevice: false}
	if r.DeadlineClosed || w.state.Recovery != nil && w.state.Recovery.SessionClosed {
		out.State = "expired-pending"
	}
	if r.AcceptedSequence != 0 {
		out.State = "accepted-not-applied"
	}
	if r.Applied {
		out.State = "trusted"
		out.TrustedDevice = true
	}
	return out
}
func (w *Workflow) RecoveredDeviceInfo() (RecoveredDeviceInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return RecoveredDeviceInfo{}, ErrClosed
	}
	return w.recoveredDeviceInfo(), nil
}
func (w *Workflow) recoveredDevicePending() bool {
	return w.state.RecoveredDevice != nil && !w.state.RecoveredDevice.Applied
}
func recoveredRecordAuthority(r *recoveredDeviceRecord) (*cryptox.VerifiedRecoveryAuthority, error) {
	v, err := cryptox.VerifyRecoveryInitialization(r.Pin, r.OriginalInitialization)
	if err != nil {
		return nil, err
	}
	for _, a := range r.Transitions {
		v, err = cryptox.VerifyAcceptedRecoveryTransition(v, a)
		if err != nil {
			return nil, err
		}
	}
	return v, nil
}
func (w *Workflow) validateRecoveredDeviceRecord() error {
	r := w.state.RecoveredDevice
	if r == nil {
		return nil
	}
	e := r.Packet.Enrollment
	if r.Version != 1 || r.CreatedAt <= 0 || r.SessionEpoch != w.engine.State().SessionEpoch || e.AccountID != w.state.AccountID || e.AccountGeneration != w.state.AccountGeneration || e.DeviceID != w.state.DeviceID || e.DeviceSigningPublicKey != w.state.SigningPublicKey || e.DeviceReceivingPublicKey != w.state.ReceivingPublicKey || r.Pin.AccountID != e.AccountID || r.Pin.AccountGeneration != e.AccountGeneration || w.state.EnrollmentV3 != nil || w.state.Pending != nil {
		return ErrRecoveryEvidence
	}
	h, err := cryptox.RecoveredDeviceReferenceHash(r.Packet)
	if err != nil || h != r.ContentHash {
		return ErrRecoveryEvidence
	}
	v, err := recoveredRecordAuthority(r)
	if err != nil {
		return err
	}
	expected := parseAuthoritySequence(e.ExpectedSequence)
	if expected >= 9007199254740991 || r.AcceptedSequence != 0 && r.AcceptedSequence != expected+1 {
		return ErrRecoveryEvidence
	}
	if _, err = cryptox.VerifyAcceptedRecoveredDevice(v, cryptox.AcceptedRecoveredDevice{Submission: r.Packet, Sequence: expected + 1}); err != nil {
		return err
	}
	if r.AcceptedSequence == 0 && r.Evidence != nil {
		return ErrRecoveryEvidence
	}
	if r.AcceptedSequence != 0 {
		proof, err := cryptox.BuildRecoveredDeviceIssuerEvidence(r.Pin, r.OriginalInitialization, r.Transitions, cryptox.AcceptedRecoveredDevice{Submission: r.Packet, Sequence: r.AcceptedSequence})
		if err != nil || r.Evidence == nil || !sameJSONValue(proof, *r.Evidence) {
			return ErrRecoveryEvidence
		}
	}
	if r.Applied {
		if r.AcceptedSequence == 0 || w.state.Root == nil || w.state.Recovery != nil || w.state.RecoveryAuthority != nil || *w.state.Root != r.Evidence.TrustRoot || w.engine.State().Cloud.Sequence < r.AcceptedSequence {
			return ErrRecoveryEvidence
		}
		verifier, err := w.recoveredVerifier()
		if err != nil {
			return err
		}
		defer verifier.Close()
		return verifier.ValidateStoredIssuerEvidence(w.engine.State().Cloud)
	}
	if w.state.Root != nil || w.engine.State().Cloud.AccountID != "" || w.state.Recovery == nil || w.state.RecoveryAuthority == nil || e.RestrictedSessionHash != w.state.Recovery.SessionHash || w.state.RecoveryAuthority.Pending == nil || !w.state.RecoveryAuthority.Pending.Applied {
		return ErrRecoveryEvidence
	}
	return nil
}
func (w *Workflow) recoveredVerifier() (*syncclient.PinnedVerifier, error) {
	r := w.state.RecoveredDevice
	if r == nil || r.AcceptedSequence == 0 || r.Evidence == nil {
		return nil, ErrRecoveryPending
	}
	generation, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil {
		return nil, err
	}
	return syncclient.NewRecoveredDevicePinnedVerifier(syncclient.RecoveredDevicePinnedTrust{Trust: syncclient.PinnedTrust{AccountID: w.state.AccountID, AccountGeneration: generation, DeviceID: w.state.DeviceID, DeviceSigningPublicKey: w.signing.Public().(ed25519.PublicKey), ReceivingPrivateKey: w.receiving, Now: w.now}, Pin: r.Pin, Evidence: *r.Evidence, Accepted: cryptox.AcceptedRecoveredDevice{Submission: r.Packet, Sequence: r.AcceptedSequence}})
}

func (s *RecoverySession) signRecoveredDevice(v *cryptox.VerifiedRecoveryAuthority, p cryptox.RecoveredDeviceSubmission, now time.Time) (string, error) {
	// All inputs originate inside the authenticated Workflow; this method is private
	// and offers no caller-controlled raw signing domain.
	if s == nil {
		return "", ErrRecoverySession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.liveLocked(); err != nil {
		return "", err
	}
	e, b := p.Enrollment, s.binding
	if b.AccountID != e.AccountID || b.AccountGeneration != e.AccountGeneration || b.RecoveryGeneration != e.RecoveryGeneration || b.AuthorityHeadHash != v.HeadHash() || b.SessionHash != e.RestrictedSessionHash || b.DeviceID != e.DeviceID || b.DeviceSigningPublicKey != e.DeviceSigningPublicKey || b.DeviceReceivingPublicKey != e.DeviceReceivingPublicKey || now.Unix() >= b.ExpiresAt {
		return "", ErrRecoverySession
	}
	return cryptox.SignRecoveredDeviceByRecovery(v, p, s.signing, now)
}

// RegisterRecoveredDevice seals the exact selected-rights packet before POST.
// The device countersignature is produced only after mature crypto opens every
// HPKE envelope with this device's actual receiving private key.
func (w *Workflow) RegisterRecoveredDevice(ctx context.Context, id string, selections []RecoveryDeviceSelection) (RecoveredDeviceInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.authoritySessionLive(); err != nil {
		return w.recoveredDeviceInfo(), err
	}
	a, r := w.state.RecoveryAuthority, w.state.Recovery
	if a.Pending == nil || !a.Pending.Applied || a.Vault.RotationRequired || w.state.RecoveredDevice != nil || !identifier.MatchString(id) || len(id) > 64 || len(selections) == 0 || len(selections) > 256 {
		return w.recoveredDeviceInfo(), ErrRecoveryRestricted
	}
	if err := w.refreshAuthorityVault(ctx); err != nil {
		return w.recoveredDeviceInfo(), err
	}
	authority, err := verifyRecoveryAuthorityChain(a.Vault)
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	var c recoveredDeviceChallenge
	created := w.now().Unix()
	if err = w.recoveryRequest(ctx, w.accountPath(recoveryAuthorityPath("recovered-device-challenges")), map[string]string{"operationId": id, "deviceId": w.state.DeviceID, "deviceSigningPublicKey": w.state.SigningPublicKey, "deviceReceivingPublicKey": w.state.ReceivingPublicKey}, &c); err != nil {
		return w.recoveredDeviceInfo(), err
	}
	if c.ExpiresAt <= created || c.ExpiresAt > created+125 || c.RestrictedSessionHash != r.SessionHash || c.ExpectedSequence != strconv.FormatUint(a.Vault.Sequence, 10) || c.RecoveryGeneration != r.RecoveryGeneration || c.RecoveryTransitionHash != authority.HeadHash() || c.IssuerEvidence.TrustRoot != r.Root {
		return w.recoveredDeviceInfo(), ErrRecoveryEvidence
	}
	pin, err := recoveryAuthorityPin(a.Vault.recoveryVaultWire)
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	source, err := cryptox.VerifyIssuerEvidenceV2(pin, c.IssuerEvidence, authority.InitialAuthorities()...)
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	selections = append([]RecoveryDeviceSelection(nil), selections...)
	sort.Slice(selections, func(i, j int) bool { return selections[i].EnvironmentID < selections[j].EnvironmentID })
	targets := map[string]string{}
	for _, t := range c.IssuerEvidence.Targets {
		targets[t.EnvironmentID] = t.AuthorityHash
	}
	kvs := map[string]string{}
	for _, e := range r.Vault.Environments {
		kvs[e.EnvironmentID] = e.KeyVersion
	}
	p := cryptox.RecoveredDeviceSubmission{CertificateVersion: "4", Capabilities: []string{cryptox.RecoveryAuthorityCapability}, IssuerEvidence: c.IssuerEvidence, SelectedRights: []cryptox.RecoveredDeviceRight{}, Grants: []cryptox.SignedGrantWire{}, Envelopes: []cryptox.RecoveryEnvelope{}}
	for i, s := range selections {
		expiry, err := strconv.ParseInt(s.ExpiresAt, 10, 64)
		if err != nil || expiry < 0 || strconv.FormatInt(expiry, 10) != s.ExpiresAt || expiry != 0 && expiry <= created || i > 0 && s.EnvironmentID == selections[i-1].EnvironmentID || s.Role != "ro" && s.Role != "rw" && s.Role != "admin" {
			return w.recoveredDeviceInfo(), ErrRecoveryEvidence
		}
		g, ok := source.Authority(targets[s.EnvironmentID])
		kv := kvs[s.EnvironmentID]
		if !ok || kv == "" || g.Grant.EnvironmentID != s.EnvironmentID || g.Grant.KeyVersion != kv {
			return w.recoveredDeviceInfo(), ErrRecoveryEvidence
		}
		key, err := cryptox.DecodeBase64(r.Keys[s.EnvironmentID], 32, 32)
		if err != nil {
			return w.recoveredDeviceInfo(), err
		}
		wrapped, err := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: r.AccountID, AccountGeneration: r.AccountGeneration, EnvironmentID: s.EnvironmentID, KeyVersion: kv, RecipientType: "device", RecipientID: w.state.DeviceID, RecipientGeneration: "1", RecipientPublicKey: w.state.ReceivingPublicKey})
		clear(key)
		if err != nil {
			return w.recoveredDeviceInfo(), err
		}
		envelope := cryptox.EncodeBase64(wrapped)
		grant, err := cryptox.SignGrant(cryptox.Grant{AccountID: r.AccountID, AccountGeneration: r.AccountGeneration, EnvironmentID: s.EnvironmentID, KeyVersion: kv, GrantGeneration: "1", IdempotencyKey: id + "-grant-" + strconv.Itoa(i), SubjectDeviceID: w.state.DeviceID, SubjectSigningPublicKey: w.state.SigningPublicKey, SubjectReceivingPublicKey: w.state.ReceivingPublicKey, Role: s.Role, ExpiresAt: s.ExpiresAt, IssuerDeviceID: w.state.DeviceID, Envelope: envelope}, w.signing)
		if err != nil {
			return w.recoveredDeviceInfo(), err
		}
		p.SelectedRights = append(p.SelectedRights, cryptox.RecoveredDeviceRight{EnvironmentID: s.EnvironmentID, KeyVersion: kv, Role: s.Role, ExpiresAt: s.ExpiresAt})
		p.Grants = append(p.Grants, cryptox.SignedGrantWire{Grant: grant.Grant, Signature: grant.Signature})
		p.Envelopes = append(p.Envelopes, cryptox.RecoveryEnvelope{EnvironmentID: s.EnvironmentID, KeyVersion: kv, Envelope: envelope})
	}
	rights, err := cryptox.RecoveredDeviceRightsHash(p.SelectedRights)
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	grants, err := cryptox.RecoveredDeviceGrantsHash(p.Grants)
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	evidence, err := cryptox.RecoveryIssuerEvidenceHash(p.IssuerEvidence)
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	envs, err := cryptox.RecoveredDeviceEnvelopesHash(p.Envelopes)
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	p.Enrollment = cryptox.RecoveredDeviceEnrollment{AccountID: r.AccountID, AccountGeneration: r.AccountGeneration, RecoveryGeneration: r.RecoveryGeneration, RecoveryTransitionHash: authority.HeadHash(), OperationID: id, ChallengeID: c.ChallengeID, Nonce: c.Nonce, ExpiresAt: strconv.FormatInt(c.ExpiresAt, 10), RestrictedSessionHash: r.SessionHash, ExpectedSequence: c.ExpectedSequence, DeviceID: w.state.DeviceID, DeviceSigningPublicKey: w.state.SigningPublicKey, DeviceReceivingPublicKey: w.state.ReceivingPublicKey, SelectedRightsHash: rights, GrantsHash: grants, IssuerEvidenceHash: evidence, EnvelopesHash: envs}
	// Validate the complete typed challenge before waiting. The original expiry,
	// source evidence, selections and all key-version bindings stay unchanged.
	if _, err = p.Enrollment.SigningBytes(); err != nil {
		return w.recoveredDeviceInfo(), errors.Join(ErrRecoveryEvidence, err)
	}
	if err = w.waitRecoveredDeviceChallenge(ctx, c.ExpiresAt); err != nil {
		return w.recoveredDeviceInfo(), err
	}
	p.RecoverySignature, err = w.recoverySession.signRecoveredDevice(authority, p, w.now())
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	p.DeviceSignature, err = cryptox.SignRecoveredDeviceAfterHPKE(authority, p, w.signing, w.receiving, w.now())
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	hash, err := cryptox.RecoveredDeviceReferenceHash(p)
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	original, err := recoveryOriginalRecord(a.Vault.recoveryVaultWire)
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	record := &recoveredDeviceRecord{Version: 1, CreatedAt: created, SessionEpoch: w.engine.State().SessionEpoch, Pin: pin, OriginalInitialization: original, Transitions: clone(a.Vault.Transitions), Packet: p, ContentHash: hash}
	w.state.RecoveredDevice = record
	if err = w.persist(); err != nil {
		return w.recoveredDeviceInfo(), err
	}
	w.recoverySession.Close()
	w.recoverySession = nil
	return w.retryRecoveredDevice(ctx, id)
}
func (w *Workflow) RetryRecoveredDevice(ctx context.Context, id string) (RecoveredDeviceInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.retryRecoveredDevice(ctx, id)
}
func (w *Workflow) retryRecoveredDevice(ctx context.Context, id string) (RecoveredDeviceInfo, error) {
	r := w.state.RecoveredDevice
	if w.closed {
		return RecoveredDeviceInfo{}, ErrClosed
	}
	if r == nil || r.Packet.Enrollment.OperationID != id {
		return w.recoveredDeviceInfo(), ErrRecoveryPending
	}
	if r.Applied {
		return w.recoveredDeviceInfo(), nil
	}
	if err := w.recoveryLive(); err != nil {
		return w.recoveredDeviceInfo(), err
	}
	if err := w.persist(); err != nil {
		return w.recoveredDeviceInfo(), err
	}
	if w.recoverySession != nil {
		w.recoverySession.Close()
		w.recoverySession = nil
	}
	var s recoveryAuthorityStatus
	if err := w.recoveryRequest(ctx, w.accountPath(recoveryAuthorityPath("recovered-devices/"+id)), nil, &s); err != nil {
		return w.recoveredDeviceInfo(), errors.Join(ErrRecoveryPending, err)
	}
	if s.OperationID != id {
		return w.recoveredDeviceInfo(), ErrRecoveryEvidence
	}
	if !s.Accepted {
		if s.Sequence != 0 || s.ContentHash != "" || s.TransitionHash != "" || s.RecoveryEnrollmentHash != "" || r.AcceptedSequence != 0 {
			return w.recoveredDeviceInfo(), ErrRecoveryEvidence
		}
		expires, _ := strconv.ParseInt(r.Packet.Enrollment.ExpiresAt, 10, 64)
		if r.DeadlineClosed || w.now().Unix() >= expires || w.now().Unix() < r.CreatedAt-5 {
			r.DeadlineClosed = true
			err := w.persist()
			return w.recoveredDeviceInfo(), errors.Join(ErrRecoveryExpired, err)
		}
		var receipt recoveryAuthorityReceipt
		if err := w.recoveryRequest(ctx, w.accountPath(recoveryAuthorityPath("recovered-devices")), r.Packet, &receipt); err != nil {
			return w.recoveredDeviceInfo(), errors.Join(ErrRecoveryPending, err)
		}
		if err := verifyAuthorityReceipt(receipt, id, r.ContentHash, r.Packet.Enrollment.ExpectedSequence, true); err != nil {
			return w.recoveredDeviceInfo(), err
		}
		s = recoveryAuthorityStatus{OperationID: id, Accepted: true, Sequence: receipt.Sequence, ContentHash: receipt.ContentHash, RecoveryEnrollmentHash: receipt.RecoveryEnrollmentHash}
	}
	if err := verifyAuthorityReceipt(recoveryAuthorityReceipt{Sequence: s.Sequence, ContentHash: s.ContentHash, TransitionHash: s.TransitionHash, RecoveryEnrollmentHash: s.RecoveryEnrollmentHash}, id, r.ContentHash, r.Packet.Enrollment.ExpectedSequence, true); err != nil {
		return w.recoveredDeviceInfo(), err
	}
	r.AcceptedSequence = s.Sequence
	proof, err := cryptox.BuildRecoveredDeviceIssuerEvidence(r.Pin, r.OriginalInitialization, r.Transitions, cryptox.AcceptedRecoveredDevice{Submission: r.Packet, Sequence: r.AcceptedSequence})
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	r.Evidence = &proof
	if err = w.persist(); err != nil {
		return w.recoveredDeviceInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	return w.applyRecoveredDevice(ctx)
}
func (w *Workflow) applyRecoveredDevice(ctx context.Context) (RecoveredDeviceInfo, error) {
	r := w.state.RecoveredDevice
	before := clone(w.state)
	oldCloud := w.engine.State()
	v, err := w.recoveredVerifier()
	if err != nil {
		return w.recoveredDeviceInfo(), err
	}
	generation, _ := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	rollback := func(e error) (RecoveredDeviceInfo, error) {
		if w.verifier != nil {
			w.verifier.Close()
		}
		w.verifier = nil
		w.client = nil
		v.Close()
		w.state = before
		w.store.state = oldCloud
		w.engine, _ = localstate.New(w.store)
		return w.recoveredDeviceInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, e)
	}
	if err = w.engine.CompleteEnrollmentAtEpoch(r.SessionEpoch); err != nil {
		return rollback(err)
	}
	c, err := syncclient.NewForBoot(syncclient.Config{Endpoint: w.state.Endpoint, HTTPClient: w.http, AccountID: w.state.AccountID, AccountGeneration: generation, DeviceID: w.state.DeviceID, Engine: w.engine, Verifier: v, Now: w.now})
	if err != nil {
		return rollback(err)
	}
	if c, err = c.BootDevice(ctx, w.signing); err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			v.Close()
			return w.recoveredDeviceInfo(), errors.Join(err, w.invalidateTrust())
		}
		return rollback(err)
	}
	pulled, err := c.Pull(ctx)
	if err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			v.Close()
			return w.recoveredDeviceInfo(), errors.Join(err, w.invalidateTrust())
		}
		return rollback(err)
	}
	if w.engine.State().Cloud.Sequence < r.AcceptedSequence || len(w.engine.State().Cloud.IssuerEvidence) == 0 {
		return rollback(syncclient.ErrAcceptedNotApplied)
	}
	if err = v.ValidateStoredIssuerEvidence(w.engine.State().Cloud); err != nil {
		return rollback(err)
	}
	root := r.Evidence.TrustRoot
	w.state.Root = &root
	w.state.Grants = []cryptox.SignedGrantWire{}
	for _, g := range pulled.Grants {
		w.state.Grants = append(w.state.Grants, cryptox.SignedGrantWire{Grant: g.Grant, Signature: g.Signature})
	}
	w.clearRecovery()
	r.Applied = true
	w.state.RecoveredDevice = r
	if err = w.persist(); err != nil {
		return rollback(err)
	}
	if w.verifier != nil {
		w.verifier.Close()
	}
	w.verifier = v
	w.client = c
	return w.recoveredDeviceInfo(), nil
}
