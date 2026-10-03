package syncclient

import (
	"github.com/harmonia-vault/core-go/cryptox"
)

// DAGRecoveryBinding 只供 Go owner 比较；不是认证凭据、wire 或原生能力。
// 所有字段来自同一已验证 session，不能由调用方替换或用于自由签名。
type DAGRecoveryBinding struct {
	Profile, Endpoint, AccountID                         string
	AccountGeneration                                    uint64
	Pin                                                  cryptox.PinnedIssuerRoot
	InitializationProposalHash, InitializationHash       string
	RecoveryGeneration, RecoveryHeadHash                 string
	RecoverySigningPublicKey, RecoveryReceivingPublicKey string
	SessionHash                                          string
	ExpiresAt                                            int64
	RotationRequired                                     bool
	PendingKind, PendingID, PendingHash                  string
}

func (DAGRecoveryBinding) String() string               { return "verified DAG binding (process only)" }
func (DAGRecoveryBinding) GoString() string             { return "verified DAG binding (process only)" }
func (DAGRecoveryBinding) MarshalJSON() ([]byte, error) { return nil, ErrDAGRecoveryState }
func (DAGRecoveryBinding) MarshalText() ([]byte, error) { return nil, ErrDAGRecoveryState }

func (s *DAGRecoverySession) VerifiedBinding() (DAGRecoveryBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifiedBindingLocked()
}
func (s *DAGRecoverySession) verifiedBindingLocked() (DAGRecoveryBinding, error) {
	if err := s.live(); err != nil {
		return DAGRecoveryBinding{}, err
	}
	if s.proof == nil || s.token == "" {
		return DAGRecoveryBinding{}, ErrDAGRecoveryState
	}
	checkpoint, err := s.proof.RecoveryCheckpoint()
	if err != nil {
		return DAGRecoveryBinding{}, err
	}
	initial, err := s.vault.DependencyBundle.Initialization.Hash()
	if err != nil {
		return DAGRecoveryBinding{}, err
	}
	if checkpoint.AccountID != s.config.AccountID || checkpoint.AccountGeneration != s.pin.AccountGeneration || checkpoint.RecoveryGeneration != s.vault.RecoveryGeneration || checkpoint.TransitionHead != s.vault.RecoveryHeadHash || checkpoint.SigningPublicKey != cryptox.EncodeBase64(s.keys.SigningPublic) || checkpoint.ReceivingPublicKey != cryptox.EncodeBase64(s.keys.ReceivingPublic) {
		return DAGRecoveryBinding{}, ErrDAGRecoveryState
	}
	b := DAGRecoveryBinding{Profile: cryptox.RecoveryDAGCapability, Endpoint: s.config.Endpoint, AccountID: s.config.AccountID, AccountGeneration: s.config.AccountGeneration, Pin: s.pin, InitializationProposalHash: s.vault.DependencyBundle.Initialization.Proof.ProposalHash, InitializationHash: initial, RecoveryGeneration: checkpoint.RecoveryGeneration, RecoveryHeadHash: checkpoint.TransitionHead, RecoverySigningPublicKey: checkpoint.SigningPublicKey, RecoveryReceivingPublicKey: checkpoint.ReceivingPublicKey, SessionHash: digest([]byte(s.token)), ExpiresAt: s.expires, RotationRequired: s.vault.RotationRequired}
	if s.pending != nil {
		if err := s.checkPending(); err != nil {
			return DAGRecoveryBinding{}, err
		}
		b.PendingKind, b.PendingID, b.PendingHash = s.pending.Kind, s.pending.OperationID, s.pending.ContentHash
	}
	return b, nil
}
