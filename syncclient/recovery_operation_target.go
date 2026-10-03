package syncclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"strconv"
)

var ErrRecoveryResolutionUnsupported = errors.New("original recovery kind or stage is not supported for closure")

// 仅原保护完整transition包可构造target；不接受网络目录或调用者提供的选择。
func RecoveryOperationTargetFromSealedTransition(binding DAGJournalBinding, raw []byte, deviceID, ed, x string) (cryptox.RecoveryOperationTarget, error) {
	var out cryptox.RecoveryOperationTarget
	p, e := DecodeDAGJournal(binding, raw)
	if e != nil {
		return out, e
	}
	if p.Kind != "transition-v2" || p.Transition == nil || p.Transition.Submission.Transition.AuthorizationKind != "old-recovery" {
		return out, ErrRecoveryResolutionUnsupported
	}
	command := p.Transition
	s := command.Submission
	t := s.Transition
	normalized := cloneDAGOperation(p)
	normalized.Attempted = false
	normalized.AcceptedSequence = 0
	normalized.Applied = false
	declared, e := json.Marshal(normalized)
	if e != nil {
		return out, e
	}
	hash := sha256.Sum256(declared)
	intent := hex.EncodeToString(hash[:])
	initial, e := command.DependencyBundle.Initialization.Hash()
	if e != nil {
		return out, e
	}
	basis, e := cryptox.RecoveryOperationDependencyBasisHash(command.DependencyBundle)
	if e != nil {
		return out, e
	}
	manifest, e := cryptox.RecoveryManifestHash(s.EnvironmentManifest)
	if e != nil {
		return out, e
	}
	challenge, e := cryptox.RecoveryOperationTransitionChallengeHash(cryptox.RecoveryOperationTransitionChallenge{AccountID: p.AccountID, AccountGeneration: t.AccountGeneration, OperationID: t.OperationID, ChallengeID: t.ChallengeID, Nonce: t.Nonce, ExpiresAt: t.ExpiresAt, SessionHash: t.SessionHash, AuthorizationKind: t.AuthorizationKind, ChainMode: t.ChainMode, AuthorizerDeviceID: t.AuthorizerDeviceID, ExpectedSequence: t.ExpectedSequence, PreviousTransitionHash: t.PreviousTransitionHash, OldRecoveryGeneration: t.OldRecoveryGeneration, OldRecoverySigningPublicKey: t.OldRecoverySigningPublicKey, OldRecoveryReceivingPublicKey: t.OldRecoveryReceivingPublicKey, EnvironmentManifest: s.EnvironmentManifest, AuthoritySet: s.AuthoritySet, IssuerEvidence: s.IssuerEvidence, DependencyBundle: command.DependencyBundle})
	if e != nil {
		return out, e
	}
	out = cryptox.RecoveryOperationTarget{Profile: cryptox.RecoveryDAGCapability, Kind: p.Kind, AccountID: p.AccountID, AccountGeneration: t.AccountGeneration, OperationID: p.OperationID, OriginalSessionHash: t.SessionHash, AuthorizationKind: t.AuthorizationKind, DeviceID: deviceID, DeviceSigningPublicKey: ed, DeviceReceivingPublicKey: x, Stage: "sealed", Basis: cryptox.RecoveryOperationBasis{InitializationHash: initial, ExpectedSequence: t.ExpectedSequence, RecoveryGeneration: t.OldRecoveryGeneration, RecoveryHeadHash: t.PreviousTransitionHash, RecoverySigningPublicKey: t.OldRecoverySigningPublicKey, RecoveryReceivingPublicKey: t.OldRecoveryReceivingPublicKey, DependencyBundleHash: basis, EnvironmentManifestHash: manifest}, DeclaredIntentHash: intent, KnownChallengeHash: challenge, DeclaredContentHash: p.ContentHash}
	_, e = out.CanonicalBytes()
	return out, e
}

// 已保护history是只读已见下界；不能通过当前网络候选替换原pin。
func validateDAGHistoryCheckpoint(c DAGRecoveryConfig, v DAGVault, current *cryptox.VerifiedRecoveryDAG) error {
	if v.Sequence < c.MinimumSequence {
		return cryptox.ErrInvalidWire
	}
	if e := ValidateDAGClosedHistory(c.ClosedOperations, v.DependencyBundle.Records); e != nil {
		return e
	}
	if e := ValidateDAGClosedHistory(c.ClosedOperations, v.IssuerEvidence.Records); e != nil {
		return e
	}
	if c.PriorBundle == nil {
		return nil
	}
	if c.Pin == nil {
		return cryptox.ErrInvalidWire
	}
	prior, e := cryptox.VerifyRecoveryDependencyBundle(*c.Pin, *c.PriorBundle)
	if e != nil {
		return e
	}
	if _, e = cryptox.VerifyRecoveryDAGAdvance(prior, v.IssuerEvidence); e != nil {
		return e
	}
	rows := map[string]cryptox.RecoveryDAGRecord{}
	for _, row := range v.DependencyBundle.Records {
		ref, e := row.Reference()
		if e != nil {
			return e
		}
		rows[ref.Kind+"/"+ref.ReferenceHash] = row
	}
	for _, row := range c.PriorBundle.Records {
		ref, e := row.Reference()
		if e != nil {
			return e
		}
		other, ok := rows[ref.Kind+"/"+ref.ReferenceHash]
		if !ok || !sameJSON(row, other) {
			return cryptox.ErrInvalidSignature
		}
	}
	if current == nil {
		return cryptox.ErrInvalidWire
	}
	return nil
}
func recoveryOperationExpected(target cryptox.RecoveryOperationTarget) uint64 {
	v, _ := strconv.ParseUint(target.Basis.ExpectedSequence, 10, 64)
	return v
}
