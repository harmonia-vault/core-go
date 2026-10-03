package mobileworkflow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/pairing"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrMobileEnrollmentPending = errors.New("original mobile enrollment outcome pending; resume the protected receipt")
var ErrMobileEnrollmentExpired = errors.New("original mobile enrollment session expired; no implicit replacement")

type EnrollmentInput struct {
	PairingID        string
	ApproverDeviceID string
	ShortCode        []byte `json:"-"`
}
type MobileEnrollmentInfo struct {
	State         string `json:"state"`
	PairingID     string `json:"pairingId,omitempty"`
	Sequence      uint64 `json:"sequence,omitempty"`
	ExpiresAt     int64  `json:"expiresAt,omitempty"`
	TrustedDevice bool   `json:"trustedDevice"`
}

// Only a locally PAKE-confirmed, double-signed receipt may be sealed here. The
// random login bearer is pending native-only material, never a Dart result.
type mobileEnrollmentRecord struct {
	Version        int                            `json:"version"`
	SessionEpoch   uint64                         `json:"sessionEpoch"`
	CreatedAt      int64                          `json:"createdAt"`
	LastObservedAt int64                          `json:"lastObservedAt"`
	SessionClosed  bool                           `json:"sessionClosed,omitempty"`
	Login          *syncclient.LoginResult        `json:"login,omitempty"`
	Receipt        syncclient.EnrollmentReceiptV3 `json:"receipt"`
	Sequence       uint64                         `json:"sequence,omitempty"`
	Applied        bool                           `json:"applied,omitempty"`
}

func (w *Workflow) enrollmentPending() bool {
	return w.state.EnrollmentV3 != nil && !w.state.EnrollmentV3.Applied
}
func (w *Workflow) mobileEnrollmentGate() error {
	if w.dagPersistenceFailed {
		return ErrDAGPersistence
	}
	if w.state.RecoveryDAG != nil || w.state.RecoveryDAGPreparation != nil {
		return ErrRecoveryRestricted
	}
	if w.closed {
		return ErrClosed
	}
	if len(w.state.SelfRevocation) > 0 {
		return ErrSelfRevocationPending
	}
	if w.state.Recovery != nil {
		return ErrRecoveryRestricted
	}
	if w.approvalV4Pending() || w.state.PendingApproval != nil && w.state.PendingApproval.Sequence == 0 || w.state.PendingApprovalV3 != nil && w.state.PendingApprovalV3.Sequence == 0 {
		return ErrApprovalPending
	}
	return nil
}
func (w *Workflow) validateMobileEnrollment() error {
	r := w.state.EnrollmentV3
	if r == nil {
		return nil
	}
	if r.Version != 1 || r.SessionEpoch != w.engine.State().SessionEpoch || r.CreatedAt <= 0 || r.CreatedAt > w.now().Unix()+5 || r.LastObservedAt < r.CreatedAt || w.state.Pending != nil || w.state.Recovery != nil || w.state.Cloud.AccountClosed {
		return errors.New("protected mobile enrollment epoch/context invalid")
	}
	raw, err := json.Marshal(r.Receipt)
	if err != nil {
		return err
	}
	if _, err = syncclient.DecodeEnrollmentReceiptV3(raw); err != nil {
		return err
	}
	gen, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil || gen == 0 {
		return ErrNotTrusted
	}
	verifier, err := syncclient.NewPinnedVerifierV3(syncclient.IssuerOriginPinnedTrust{AccountID: w.state.AccountID, AccountGeneration: gen, DeviceID: w.state.DeviceID, DeviceSigningPublicKey: w.signing.Public().(ed25519.PublicKey), ReceivingPrivateKey: w.receiving, Receipt: r.Receipt, Now: w.now})
	if err != nil {
		return err
	}
	defer verifier.Close()
	if r.Sequence == 0 {
		if r.Applied {
			return errors.New("unacknowledged enrollment cannot be applied")
		}
		if w.state.Root != nil || w.state.Cloud.Cloud.AccountID != "" || r.Login == nil || r.Login.AccountID != w.state.AccountID || r.Login.AccountGeneration != w.state.AccountGeneration || r.Login.ExpiresAt <= r.CreatedAt {
			return errors.New("unacknowledged mobile enrollment cannot claim trust")
		}
		if r.SessionClosed {
			if r.Login.Token != "" {
				return errors.New("expired mobile enrollment retained bearer")
			}
		} else if _, err = cryptox.DecodeBase64(r.Login.Token, 32, 32); err != nil {
			return err
		}
	} else {
		if r.Sequence > 9007199254740991 || r.Login != nil || w.state.Root == nil || *w.state.Root != r.Receipt.Approval.IssuerProof.TrustRoot {
			return errors.New("accepted mobile enrollment root/receipt invalid")
		}
		if err = verifier.ValidateStoredIssuerEvidence(w.engine.State().Cloud); err != nil {
			return err
		}
		if r.Applied && (w.engine.State().Cloud.Sequence < r.Sequence || len(w.engine.State().Cloud.IssuerEvidence) == 0) {
			return errors.New("applied enrollment requires verified accepted checkpoint and ledger")
		}
	}
	return nil
}
func (w *Workflow) observeEnrollmentClock() error {
	r := w.state.EnrollmentV3
	if r == nil || r.Sequence != 0 {
		return nil
	}
	now := w.now().Unix()
	if now < r.LastObservedAt-5 {
		return ErrMobileEnrollmentExpired
	}
	changed := false
	if now > r.LastObservedAt {
		r.LastObservedAt = now
		changed = true
	}
	if !r.SessionClosed && r.Login != nil && now >= r.Login.ExpiresAt {
		r.Login.Token = ""
		r.SessionClosed = true
		changed = true
	}
	if changed {
		return w.persist()
	}
	return nil
}
func (w *Workflow) EnrollmentInfo() (MobileEnrollmentInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.mobileEnrollmentGate(); err != nil {
		return MobileEnrollmentInfo{}, err
	}
	if err := w.observeEnrollmentClock(); err != nil {
		return MobileEnrollmentInfo{}, err
	}
	r := w.state.EnrollmentV3
	if r == nil {
		return MobileEnrollmentInfo{State: "none"}, nil
	}
	out := MobileEnrollmentInfo{State: "pending", PairingID: r.Receipt.IdempotencyKey, Sequence: r.Sequence}
	if r.Sequence > 0 {
		out.State = "complete"
		if !r.Applied {
			out.State = "accepted-not-applied"
		}
		out.TrustedDevice = r.Applied
	} else if r.Login != nil {
		out.ExpiresAt = r.Login.ExpiresAt
		if r.SessionClosed {
			out.State = "expired-pending"
		}
	}
	return out, nil
}
func (w *Workflow) enrollmentConfig(r *mobileEnrollmentRecord) (syncclient.EnrollmentConfig, error) {
	gen, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil || gen == 0 {
		return syncclient.EnrollmentConfig{}, ErrNotTrusted
	}
	token := ""
	if r != nil && r.Login != nil {
		token = r.Login.Token
	} else if w.login != nil {
		token = w.login.Token
	}
	return syncclient.EnrollmentConfig{Endpoint: w.state.Endpoint, HTTPClient: w.http, AccountID: w.state.AccountID, AccountGeneration: gen, DeviceID: w.state.DeviceID, LoginToken: token, SigningKey: w.signing, ReceivingPrivateKey: w.receiving, Engine: w.engine, Now: w.now}, nil
}

// EnrollDevice is one native authenticated operation. No PAKE private state or
// short code survives it. A pending complete receipt is saved before Complete.
func (w *Workflow) EnrollDevice(ctx context.Context, input EnrollmentInput) (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return View{}, err
	}
	if w.state.Root != nil || w.state.Pending != nil || w.state.EnrollmentV3 != nil || w.login == nil || w.login.ExpiresAt <= w.now().Unix() {
		return View{}, ErrNotTrusted
	}
	config, err := w.enrollmentConfig(nil)
	if err != nil {
		return View{}, err
	}
	enrollment, err := syncclient.NewEnrollmentV3(config)
	if err != nil {
		return View{}, err
	}
	defer enrollment.Close()
	if _, err = enrollment.Begin(ctx, input.ApproverDeviceID, input.PairingID, input.ShortCode); err != nil {
		return View{}, err
	}
	for {
		if _, err = enrollment.Advance(ctx); err != nil {
			return View{}, err
		}
		receipt, e := enrollment.Receipt()
		if e == nil {
			now := w.now().Unix()
			r := &mobileEnrollmentRecord{Version: 1, SessionEpoch: w.engine.State().SessionEpoch, CreatedAt: now, LastObservedAt: now, Login: w.login, Receipt: receipt}
			w.state.EnrollmentV3 = r
			w.login = nil
			if err = w.persist(); err != nil {
				return View{}, errors.Join(ErrMobileEnrollmentPending, err)
			}
			return w.completeMobileEnrollment(ctx, enrollment, r)
		}
		if !errors.Is(e, pairing.ErrState) {
			return View{}, e
		}
		select {
		case <-ctx.Done():
			return View{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
func (w *Workflow) completeMobileEnrollment(ctx context.Context, e *syncclient.EnrollmentV3, r *mobileEnrollmentRecord) (View, error) {
	result, err := e.Complete(ctx)
	if err != nil {
		return View{}, errors.Join(ErrMobileEnrollmentPending, err)
	}
	defer result.Verifier.Close()
	if result.Sequence == 0 || result.Sequence > 9007199254740991 || !sameJSONValue(result.Receipt, r.Receipt) {
		return View{}, ErrMobileEnrollmentPending
	}
	if err = w.engine.CompleteEnrollmentAtEpoch(r.SessionEpoch); err != nil {
		return View{}, err
	}
	previous := clone(r)
	r.Sequence = result.Sequence
	r.Applied = false
	r.Login = nil
	root := r.Receipt.Approval.IssuerProof.TrustRoot
	w.state.Root = &root
	if err = w.persist(); err != nil {
		w.state.Root = nil
		w.state.EnrollmentV3 = previous
		return View{}, errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	return w.applyAcceptedMobileEnrollment(ctx, r)
}

// The accepted receipt is an identity anchor, not permission to expose cached
// plaintext. Only this private path may pull while its own applied gate is shut.
func (w *Workflow) applyAcceptedMobileEnrollment(ctx context.Context, r *mobileEnrollmentRecord) (View, error) {
	if r.Sequence == 0 || w.state.Root == nil {
		return View{}, ErrMobileEnrollmentPending
	}
	r.Applied = false
	if err := w.refreshForApproval(ctx); err != nil {
		return View{}, errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	if w.engine.State().Cloud.Sequence < r.Sequence || len(w.engine.State().Cloud.IssuerEvidence) == 0 {
		return View{}, syncclient.ErrAcceptedNotApplied
	}
	if err := w.validateOriginCache(); err != nil {
		return View{}, errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	r.Applied = true
	if err := w.persist(); err != nil {
		r.Applied = false
		return View{}, errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	return w.view(), nil
}
func (w *Workflow) ResumeEnrollment(ctx context.Context, id string) (View, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.mobileEnrollmentGate(); err != nil {
		return View{}, err
	}
	if err := w.observeEnrollmentClock(); err != nil {
		return View{}, err
	}
	r := w.state.EnrollmentV3
	if r == nil || r.Receipt.IdempotencyKey != id {
		return View{}, syncclient.ErrWriteConflict
	}
	if r.Sequence > 0 {
		return w.applyAcceptedMobileEnrollment(ctx, r)
	}
	if r.SessionClosed {
		return View{}, ErrMobileEnrollmentExpired
	}
	config, err := w.enrollmentConfig(r)
	if err != nil {
		return View{}, err
	}
	e, err := syncclient.ResumeEnrollmentV3(config, r.Receipt)
	if err != nil {
		return View{}, err
	}
	defer e.Close()
	if err = w.persist(); err != nil {
		return View{}, err
	}
	return w.completeMobileEnrollment(ctx, e, r)
}
func sameJSONValue(a, b any) bool {
	aa, e := json.Marshal(a)
	bb, f := json.Marshal(b)
	return e == nil && f == nil && string(aa) == string(bb)
}
func (w *Workflow) originVerifier() (*syncclient.PinnedVerifier, error) {
	generation, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil || generation == 0 || w.state.Root == nil {
		return nil, ErrNotTrusted
	}
	if w.state.RecoveredDevice != nil {
		return w.recoveredVerifier()
	}
	if r := w.state.EnrollmentV3; r != nil {
		if r.Sequence == 0 {
			return nil, ErrMobileEnrollmentPending
		}
		return syncclient.NewPinnedVerifierV3(syncclient.IssuerOriginPinnedTrust{AccountID: w.state.AccountID, AccountGeneration: generation, DeviceID: w.state.DeviceID, DeviceSigningPublicKey: w.signing.Public().(ed25519.PublicKey), ReceivingPrivateKey: w.receiving, Receipt: r.Receipt, Now: w.now})
	}
	return syncclient.NewRootPinnedVerifierWithOrigins(syncclient.OriginRootPinnedTrust{Trust: syncclient.PinnedTrust{AccountID: w.state.AccountID, AccountGeneration: generation, DeviceID: w.state.DeviceID, DeviceSigningPublicKey: w.signing.Public().(ed25519.PublicKey), ReceivingPrivateKey: w.receiving, Now: w.now}, Root: *w.state.Root, InitialAuthorities: w.state.InitialAuthorities})
}
func (w *Workflow) originPinAndInitial() (cryptox.PinnedIssuerRoot, []cryptox.SignedGrantWire, error) {
	if w.state.Root == nil {
		return cryptox.PinnedIssuerRoot{}, nil, ErrNotTrusted
	}
	root := w.state.Root
	pin := cryptox.PinnedIssuerRoot{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, DeviceID: root.RootDeviceID, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey}
	initial := w.state.InitialAuthorities
	if r := w.state.EnrollmentV3; r != nil && r.Sequence > 0 {
		proof, err := cryptox.VerifyCompletedEnrollmentV3(cryptox.ConfirmedEnrollmentAnchor{Context: r.Receipt.Approval.Context, TranscriptHash: r.Receipt.Approval.TranscriptHash}, r.Receipt.Approval)
		if err != nil {
			return pin, nil, err
		}
		initial = proof.InitialAuthorities()
	}
	if len(initial) == 0 {
		return pin, nil, ErrApprovalEvidence
	}
	return pin, initial, nil
}
func (w *Workflow) validateOriginCache() error {
	if w.state.Root == nil {
		return nil
	}
	verifier, err := w.originVerifier()
	if err != nil {
		return err
	}
	defer verifier.Close()
	return verifier.ValidateStoredIssuerEvidence(w.engine.State().Cloud)
}
