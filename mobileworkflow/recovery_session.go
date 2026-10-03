package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
)

var ErrRecoverySession = errors.New("process-only recovery owner unavailable; interrupted recovery requires complete old code")

// Binding is public metadata for the native registry; it never crosses Dart.
// The proposal hash names the exact verified original initialization commitment,
// not a guessed root self-grant or a new recovery authority.
type RecoverySessionBinding struct {
	Endpoint                   string
	DeviceID                   string
	DeviceSigningPublicKey     string
	DeviceReceivingPublicKey   string
	AccountID                  string
	AccountGeneration          string
	RecoveryGeneration         string
	RootDeviceID               string
	RootSigningPublicKey       string
	RootReceivingPublicKey     string
	RecoverySigningPublicKey   string
	RecoveryReceivingPublicKey string
	InitializationProposalHash string
	SessionHash                string
	ExpiresAt                  int64
	TransitionID               string
	TransitionHash             string
}

// RecoverySession is an independently owned native process resource. There is
// no export of its signing material and no arbitrary signing API. Private data
// are never serialized; the receiving private key is absent altogether.
type RecoverySession struct {
	mu       sync.Mutex
	signing  ed25519.PrivateKey
	binding  RecoverySessionBinding
	now      func() time.Time
	lastWall int64
	deadline time.Time
	timer    *time.Timer
	closed   bool
}

func (*RecoverySession) String() string               { return "process-only recovery session (opaque)" }
func (*RecoverySession) GoString() string             { return "process-only recovery session (opaque)" }
func (*RecoverySession) MarshalText() ([]byte, error) { return nil, ErrRecoverySession }
func (*RecoverySession) MarshalJSON() ([]byte, error) {
	return nil, errors.New("process-only recovery owner cannot be serialized")
}
func (s *RecoverySession) clearLocked() {
	if s.closed {
		return
	}
	clear(s.signing)
	s.signing = nil
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
}
func (s *RecoverySession) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
}
func (s *RecoverySession) Cancel() { s.Close() }
func (s *RecoverySession) liveLocked() error {
	now := s.now().Unix()
	if s.closed || len(s.signing) != ed25519.PrivateKeySize || !time.Now().Before(s.deadline) || now >= s.binding.ExpiresAt || now < s.lastWall-5 {
		s.clearLocked()
		return ErrRecoverySession
	}
	if now > s.lastWall {
		s.lastWall = now
	}
	return nil
}
func (s *RecoverySession) Binding() (RecoverySessionBinding, error) {
	if s == nil {
		return RecoverySessionBinding{}, ErrRecoverySession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.liveLocked(); err != nil {
		return RecoverySessionBinding{}, err
	}
	return s.binding, nil
}
func (w *Workflow) recoverySessionBinding() (RecoverySessionBinding, error) {
	r := w.state.Recovery
	if r == nil || !r.OriginsRequired || r.SessionClosed || r.RotationCompleted || r.SessionToken == "" {
		return RecoverySessionBinding{}, ErrRecoverySession
	}
	if _, err := recoveryOriginalAuthorities(r.Vault, r.Root); err != nil {
		return RecoverySessionBinding{}, err
	}
	return RecoverySessionBinding{Endpoint: w.state.Endpoint, DeviceID: w.state.DeviceID, DeviceSigningPublicKey: w.state.SigningPublicKey, DeviceReceivingPublicKey: w.state.ReceivingPublicKey, AccountID: r.AccountID, AccountGeneration: r.AccountGeneration, RecoveryGeneration: r.RecoveryGeneration, RootDeviceID: r.Root.RootDeviceID, RootSigningPublicKey: r.Root.RootSigningPublicKey, RootReceivingPublicKey: r.Root.RootReceivingPublicKey, RecoverySigningPublicKey: r.SigningPublicKey, RecoveryReceivingPublicKey: r.ReceivingPublicKey, InitializationProposalHash: r.Vault.OriginalInitialization.Proof.ProposalHash, SessionHash: r.SessionHash, ExpiresAt: r.SessionExpiresAt}, nil
}
func (w *Workflow) newRecoverySession(key ed25519.PrivateKey) (*RecoverySession, error) {
	b, err := w.recoverySessionBinding()
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) || cryptox.EncodeBase64(key.Public().(ed25519.PublicKey)) != b.RecoverySigningPublicKey {
		return nil, ErrRecoverySession
	}
	now := w.now().Unix()
	if b.ExpiresAt > now+300 {
		b.ExpiresAt = now + 300
	}
	if b.ExpiresAt <= now {
		return nil, ErrRecoverySession
	}
	s := &RecoverySession{signing: bytes.Clone(key), binding: b, now: w.now, lastWall: now, deadline: time.Now().Add(time.Duration(b.ExpiresAt-now) * time.Second)}
	s.mu.Lock()
	s.timer = time.AfterFunc(time.Until(s.deadline), s.Close)
	s.mu.Unlock()
	if err := w.bindRecoverySessionRotation(s); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func sameRecoverySessionIdentity(a, b RecoverySessionBinding) bool {
	a.ExpiresAt, b.ExpiresAt = 0, 0
	a.TransitionID, b.TransitionID = "", ""
	a.TransitionHash, b.TransitionHash = "", ""
	return a == b
}
func (w *Workflow) bindRecoverySessionRotation(s *RecoverySession) error {
	b, err := w.recoverySessionBinding()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.liveLocked(); err != nil {
		return err
	}
	if !sameRecoverySessionIdentity(s.binding, b) || s.binding.ExpiresAt > b.ExpiresAt {
		return ErrRecoverySession
	}
	q := w.state.Recovery.Rotation
	if q == nil {
		if s.binding.TransitionID != "" {
			return ErrRecoverySession
		}
		return nil
	}
	if q.Challenge == nil {
		return ErrRecoverySession
	}
	proof, err := w.rotationProof(q, *q.Challenge)
	if err != nil {
		return err
	}
	raw, err := proof.SigningBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if s.binding.TransitionID != "" && (s.binding.TransitionID != q.Proposal.IdempotencyKey || s.binding.TransitionHash != digest) {
		return ErrRecoverySession
	}
	s.binding.TransitionID = q.Proposal.IdempotencyKey
	s.binding.TransitionHash = digest
	expires, err := strconv.ParseInt(proof.ExpiresAt, 10, 64)
	if err != nil {
		return err
	}
	if expires < s.binding.ExpiresAt {
		s.binding.ExpiresAt = expires
		deadline := time.Now().Add(time.Duration(expires-w.now().Unix()) * time.Second)
		if deadline.Before(s.deadline) {
			s.deadline = deadline
		}
		if s.timer != nil {
			s.timer.Stop()
		}
		s.timer = time.AfterFunc(time.Until(s.deadline), s.Close)
	}
	return s.liveLocked()
}

// AttachRecoverySession is called only after a new system CryptoObject operation
// authenticates and native AES verifies this Workflow's context. Native registry
// ownership outlives Workflow.Close; no session material is in protectedState.
func (w *Workflow) AttachRecoverySession(s *RecoverySession) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.recoveryLive(); err != nil {
		return err
	}
	if s == nil {
		return ErrRecoverySession
	}
	if err := w.bindRecoverySessionRotation(s); err != nil {
		return err
	}
	if w.recoverySession != nil && w.recoverySession != s {
		return ErrRecoverySession
	}
	w.recoverySession = s
	return nil
}
func (w *Workflow) BeginRecoveryWithOriginsSession(ctx context.Context, code string) (*RecoverySession, RecoveryInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var owner *RecoverySession
	info, err := w.beginRecovery(ctx, code, true, func(key ed25519.PrivateKey) error {
		var err error
		owner, err = w.newRecoverySession(key)
		if err == nil {
			w.recoverySession = owner
		}
		return err
	})
	if err != nil {
		if owner != nil {
			owner.Close()
		}
		return nil, info, err
	}
	return owner, info, nil
}

// A process interruption never substitutes a new session/nonce/ID for a sealed
// pending request. Full old-code reentry can reconstruct only this exact live
// restricted context; an already accepted rotation uses its journal/new code.
func (w *Workflow) ResumeRecoverySession(ctx context.Context, completeOldCode string) (*RecoverySession, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.recoveryLive(); err != nil {
		return nil, err
	}
	r := w.state.Recovery
	if r == nil || !r.OriginsRequired || r.RotationCompleted {
		return nil, ErrRecoverySession
	}
	if err := w.refreshRecoveryVault(ctx); err != nil {
		return nil, err
	}
	seed, err := cryptox.DecodeRecoveryCode(completeOldCode)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	keys, err := cryptox.DeriveRecoveryKeys(seed, r.AccountID, r.AccountGeneration, r.RecoveryGeneration)
	if err != nil {
		return nil, err
	}
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	if cryptox.EncodeBase64(keys.SigningPublic) != r.SigningPublicKey || cryptox.EncodeBase64(keys.ReceivingPublic) != r.ReceivingPublicKey {
		return nil, ErrRecoverySession
	}
	if w.recoverySession != nil {
		w.recoverySession.Close()
		w.recoverySession = nil
	}
	owner, err := w.newRecoverySession(keys.SigningPrivate)
	if err != nil {
		return nil, err
	}
	w.recoverySession = owner
	return owner, nil
}
