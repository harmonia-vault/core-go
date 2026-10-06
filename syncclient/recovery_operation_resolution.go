package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/harmonia-vault/core-go/cryptox"
	"io"
	"net/http"
	"strconv"
	"time"
)

type RecoveryOperationResolutionConfig struct {
	Endpoint                  string
	HTTPClient                *http.Client
	AccountID                 string
	AccountGeneration         uint64
	MinimumRecoveryGeneration uint64
	Now                       func() time.Time
}

// 此窄会话不导出token/恢复钥/general request，也不读取vault或授予管理权限。
type RecoveryOperationResolutionSession struct{ session *DAGRecoverySession }

func (*RecoveryOperationResolutionSession) String() string {
	return "process-only recovery operation resolution"
}
func (*RecoveryOperationResolutionSession) GoString() string {
	return "process-only recovery operation resolution"
}
func (*RecoveryOperationResolutionSession) MarshalJSON() ([]byte, error) {
	return nil, ErrDAGRecoveryState
}
func (*RecoveryOperationResolutionSession) MarshalText() ([]byte, error) {
	return nil, ErrDAGRecoveryState
}
func (s *RecoveryOperationResolutionSession) Close() {
	if s != nil && s.session != nil {
		s.session.Close()
	}
}
func OpenRecoveryOperationResolutionSession(ctx context.Context, c RecoveryOperationResolutionConfig, completeCode []byte) (*RecoveryOperationResolutionSession, error) {
	defer clear(completeCode)
	if ctx == nil || ctx.Err() != nil || !enrollmentID.MatchString(c.AccountID) || c.AccountGeneration == 0 || len(completeCode) == 0 || len(completeCode) > 512 {
		return nil, cryptox.ErrInvalidWire
	}
	if e := checkDAGCapabilities(ctx, c.Endpoint, c.HTTPClient, cryptox.RecoveryDAGCapability, cryptox.RecoveryOperationClosureCapability); e != nil {
		return nil, e
	}
	s, e := openDAGRecoveryProof(ctx, DAGRecoveryConfig{Endpoint: c.Endpoint, HTTPClient: c.HTTPClient, AccountID: c.AccountID, AccountGeneration: c.AccountGeneration, Now: c.Now}, string(completeCode))
	if e != nil {
		return nil, e
	}
	generation, e := strconv.ParseUint(s.authRecoveryGeneration, 10, 64)
	if e != nil || generation < c.MinimumRecoveryGeneration {
		s.Close()
		return nil, cryptox.ErrInvalidWire
	}
	return &RecoveryOperationResolutionSession{session: s}, nil
}
func (s *RecoveryOperationResolutionSession) Resolve(ctx context.Context, target cryptox.RecoveryOperationTarget, mode string, key ed25519.PrivateKey) (cryptox.RecoveryOperationResolutionReceipt, error) {
	var out cryptox.RecoveryOperationResolutionReceipt
	if target.Kind != "transition-v2" || target.Stage != "sealed" || target.AuthorizationKind != "old-recovery" {
		return out, ErrRecoveryResolutionUnsupported
	}
	if s == nil || s.session == nil || ctx == nil {
		return out, ErrDAGRecoveryState
	}
	v := s.session
	v.mu.Lock()
	defer v.mu.Unlock()
	if e := v.live(); e != nil {
		return out, e
	}
	if target.AccountID != v.config.AccountID || target.AccountGeneration != strconv.FormatUint(v.config.AccountGeneration, 10) {
		return out, cryptox.ErrInvalidWire
	}
	h := sha256.Sum256([]byte(v.token))
	sessionHash := hex.EncodeToString(h[:])
	if target.OriginalSessionHash == sessionHash {
		return out, cryptox.ErrInvalidWire
	}
	sig, e := cryptox.SignRecoveryOperationResolution(target, mode, sessionHash, key)
	if e != nil {
		return out, e
	}
	request := cryptox.RecoveryOperationResolutionRequest{Version: 1, Mode: mode, Target: target, DeviceSignature: sig}
	body, e := json.Marshal(request)
	if e != nil || len(body) > 8192 {
		return out, cryptox.ErrInvalidWire
	}
	defer clear(body)
	path := "/recovery-operation-resolutions-v1?capability=" + cryptox.RecoveryOperationClosureCapability
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, v.path(path).String(), bytes.NewReader(body))
	if e != nil {
		return out, cryptox.ErrInvalidWire
	}
	r.Header.Set("Harmonia-Protocol-Major", "2")
	r.Header.Set("X-Harmonia-Account-Generation", target.AccountGeneration)
	r.Header.Set("Authorization", "Bearer "+v.token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Cache-Control", "no-store")
	response, e := v.http.Do(r)
	if e != nil {
		return out, ErrDAGRequestUnavailable
	}
	defer response.Body.Close()
	if response.Header.Get("Harmonia-Protocol-Major") != "2" {
		return out, cryptox.ErrInvalidWire
	}
	if response.StatusCode != 200 {
		return out, ParseRequestError(response)
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 4097))
	if e != nil || len(raw) > 4096 {
		return out, cryptox.ErrInvalidWire
	}
	defer clear(raw)
	out, e = cryptox.DecodeRecoveryOperationResolutionReceipt(raw)
	if e != nil {
		return out, e
	}
	if e = out.ValidateTarget(target); e != nil {
		return out, e
	}
	if e = v.live(); e != nil {
		return out, e
	}
	if e = ctx.Err(); e != nil {
		return out, e
	}
	return out, nil
}

// 只在RAM暂存成熟原历史确认结果；最终whole-state CAS由唯一高层owner完成。
type resolutionConfirmationJournal struct {
	ctx       context.Context
	original  ProtectedDAGOperation
	confirmed *ProtectedDAGOperation
}

func (j *resolutionConfirmationJournal) OwnerAlive() error { return j.ctx.Err() }
func (j *resolutionConfirmationJournal) Load() (ProtectedDAGOperation, error) {
	if e := j.ctx.Err(); e != nil {
		return ProtectedDAGOperation{}, e
	}
	return cloneDAGOperation(j.original), nil
}
func (j *resolutionConfirmationJournal) Save(p ProtectedDAGOperation) error {
	if e := j.ctx.Err(); e != nil {
		return e
	}
	old := cloneDAGOperation(j.original)
	next := cloneDAGOperation(p)
	old.Attempted, next.Attempted = false, false
	old.AcceptedSequence, next.AcceptedSequence = 0, 0
	old.Applied, next.Applied = false, false
	if !sameJSON(old, next) || !p.Applied || p.AcceptedSequence == 0 || validateProtectedDAGOperation(p) != nil {
		return cryptox.ErrInvalidWire
	}
	value := cloneDAGOperation(p)
	j.confirmed = &value
	return nil
}
func ConfirmRecoveryOperationResolutionAccepted(ctx context.Context, c DAGRecoveryConfig, p ProtectedDAGOperation, t cryptox.RecoveryOperationTarget, receipt cryptox.RecoveryOperationResolutionReceipt, completeCode []byte) (ProtectedDAGOperation, cryptox.RecoveryDependencyBundle, uint64, error) {
	defer clear(completeCode)
	var empty cryptox.RecoveryDependencyBundle
	if ctx == nil || p.Kind != "transition-v2" || p.Transition == nil || receipt.State != "accepted" || receipt.ValidateTarget(t) != nil || receipt.ContentHash != p.ContentHash || validateProtectedDAGOperation(p) != nil {
		return ProtectedDAGOperation{}, empty, 0, cryptox.ErrInvalidWire
	}
	journal := &resolutionConfirmationJournal{ctx: ctx, original: cloneDAGOperation(p)}
	c.Journal = journal
	c.Preparation = nil
	c.RecoveredPreparation = nil
	c.Pin = &p.Pin
	session, e := OpenDAGRecoverySession(ctx, c, string(completeCode))
	if e != nil {
		return ProtectedDAGOperation{}, empty, 0, e
	}
	defer session.Close()
	out, e := session.ResolveOriginalOperation(ctx)
	if e != nil {
		return ProtectedDAGOperation{}, empty, 0, e
	}
	if !out.Accepted || out.Sequence != receipt.Sequence || out.ContentHash != receipt.ContentHash || journal.confirmed == nil {
		return ProtectedDAGOperation{}, empty, 0, cryptox.ErrInvalidWire
	}
	session.mu.Lock()
	bundle := session.vault.DependencyBundle
	sequence := session.vault.Sequence
	session.mu.Unlock()
	if e = ctx.Err(); e != nil {
		return ProtectedDAGOperation{}, empty, 0, e
	}
	return cloneDAGOperation(*journal.confirmed), bundle, sequence, nil
}
