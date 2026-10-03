package mobileworkflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

// Public accepted source packages authenticate ciphertext bytes, including for
// empty environments. An HPKE recipient's public key cannot authenticate sender.
type recoveryEnvelopeEvidence struct {
	Profile            string                     `json:"profile"`
	EnvironmentChanges []recoveryEnvelopeChange   `json:"environmentChanges"`
	RecoveryRotations  []recoveryEnvelopeRotation `json:"recoveryRotations"`
}
type recoveryEnvelopeChange struct {
	Sequence      uint64                           `json:"sequence"`
	Change        cryptox.SignedEnvironmentChange  `json:"change"`
	Origin        *cryptox.SignedEnvironmentOrigin `json:"origin"`
	Authorization cryptox.SignedGrantWire          `json:"authorization"`
}
type recoveryEnvelopeRotation struct {
	Sequence  uint64                           `json:"sequence"`
	Proposal  cryptox.RecoveryRotationProposal `json:"proposal"`
	Proof     cryptox.RecoveryRotationProof    `json:"proof"`
	Signature string                           `json:"signature"`
}

func recoveryEnvelopeGraph(v recoveryVaultWire, root cryptox.TrustRoot) (*cryptox.VerifiedIssuerProofV2, error) {
	if err := validateRecoveryEvidenceCandidate(v.IssuerEvidence); err != nil {
		return nil, err
	}
	if len(v.IssuerEvidence) == 0 || bytes.Equal(bytes.TrimSpace(v.IssuerEvidence), []byte("null")) {
		return nil, ErrRecoveryEvidence
	}
	var p cryptox.IssuerProofV2
	if err := decode(v.IssuerEvidence, &p); err != nil {
		return nil, errors.Join(ErrRecoveryEvidence, err)
	}
	if p.TrustRoot != root {
		return nil, ErrRecoveryEvidence
	}
	initial, err := recoveryOriginalAuthorities(v, root)
	if err != nil {
		return nil, err
	}
	pin := cryptox.PinnedIssuerRoot{AccountID: v.AccountID, AccountGeneration: v.AccountGeneration, DeviceID: root.RootDeviceID, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey}
	verified, err := cryptox.VerifyIssuerEvidenceV2(pin, p, initial...)
	if err != nil {
		return nil, errors.Join(ErrRecoveryEvidence, err)
	}
	return verified, nil
}

func verifyRecoveryEnvelopes(v recoveryVaultWire, root cryptox.TrustRoot, originsRequired bool) error {
	if _, err := recoveryOriginalAuthorities(v, root); err != nil {
		return err
	}
	current := make(map[string]cryptox.RecoveryEnvelope, len(v.Environments))
	proven := map[string]bool{}
	for _, e := range v.Environments {
		if _, duplicate := current[e.EnvironmentID]; duplicate {
			return ErrRecoveryEvidence
		}
		current[e.EnvironmentID] = e
	}
	i := v.OriginalInitialization.Proposal
	if i.RecoveryGeneration == v.RecoveryGeneration && i.RecoverySigningPublicKey == v.RecoverySigningPublicKey && i.RecoveryReceivingPublicKey == v.RecoveryReceivingPublicKey {
		for _, e := range i.Environments {
			if target, ok := current[e.EnvironmentID]; ok && target.KeyVersion == e.KeyVersion && target.Envelope == e.RecoveryEnvelope {
				proven[e.EnvironmentID] = true
			}
		}
	}
	ev := v.EnvelopeEvidence
	if ev != nil {
		encoded, err := json.Marshal(ev)
		if err != nil || len(encoded) > 2<<20 || ev.Profile != "harmonia/recovery-envelope-evidence/v1" || ev.EnvironmentChanges == nil || ev.RecoveryRotations == nil || len(ev.EnvironmentChanges) > 256 || len(ev.RecoveryRotations) > 128 {
			return ErrRecoveryEvidence
		}
		var graph *cryptox.VerifiedIssuerProofV2
		if len(ev.EnvironmentChanges) > 0 {
			if !originsRequired {
				return ErrRecoveryEvidence
			}
			graph, err = recoveryEnvelopeGraph(v, root)
			if err != nil {
				return err
			}
		}
		changes := map[string]bool{}
		for _, source := range ev.EnvironmentChanges {
			c := source.Change.Change
			target, ok := current[c.EnvironmentID]
			base, err := strconv.ParseUint(c.ExpectedSequence, 10, 64)
			if err != nil || base >= 9007199254740991 || source.Sequence != base+1 || source.Sequence > v.Sequence || c.AccountID != v.AccountID || c.AccountGeneration != v.AccountGeneration || !ok || c.KeyVersion != target.KeyVersion || (c.Operation != "create" && c.Operation != "rotate") || changes[c.EnvironmentID] || source.Origin == nil {
				return ErrRecoveryEvidence
			}
			changes[c.EnvironmentID] = true
			if err = graph.VerifyHistoricalGrant(source.Authorization); err != nil {
				return errors.Join(ErrRecoveryEvidence, err)
			}
			if err = graph.VerifyEnvironmentOriginEvent(source.Change, *source.Origin, source.Authorization); err != nil {
				return errors.Join(ErrRecoveryEvidence, err)
			}
			if c.RecoveryGeneration == v.RecoveryGeneration && c.RecoveryEnvelope == target.Envelope {
				proven[c.EnvironmentID] = true
			}
		}
		rotations := map[string]bool{}
		key, err := cryptox.DecodeBase64(root.RecoverySigningPublicKey, 32, 32)
		if err != nil {
			return ErrRecoveryEvidence
		}
		for _, source := range ev.RecoveryRotations {
			p, q := source.Proposal, source.Proof
			if source.Sequence == 0 || source.Sequence > v.Sequence || !identifier.MatchString(p.IdempotencyKey) || rotations[p.IdempotencyKey] || p.NewTrustRoot != root || p.NewRecoveryGeneration != v.RecoveryGeneration || p.NewRecoverySigningPublicKey != v.RecoverySigningPublicKey || p.NewRecoveryReceivingPublicKey != v.RecoveryReceivingPublicKey || q.AccountID != v.AccountID || q.AccountGeneration != v.AccountGeneration || q.NewRecoveryGeneration != p.NewRecoveryGeneration || q.NewRecoverySigningPublicKey != p.NewRecoverySigningPublicKey || q.NewRecoveryReceivingPublicKey != p.NewRecoveryReceivingPublicKey || len(p.Envelopes) == 0 {
				return ErrRecoveryEvidence
			}
			rotations[p.IdempotencyKey] = true
			h, err := cryptox.RecoveryEnvelopesHash(p.Envelopes)
			if err != nil || h != q.EnvelopesHash {
				return ErrRecoveryEvidence
			}
			h, err = p.NewTrustRoot.Hash(v.AccountID, v.AccountGeneration)
			if err != nil || h != q.TrustRootHash || cryptox.VerifyRecoveryRotationProof(q, source.Signature, key) != nil {
				return ErrRecoveryEvidence
			}
			for _, e := range p.Envelopes {
				if target, ok := current[e.EnvironmentID]; ok && target == e {
					proven[e.EnvironmentID] = true
				}
			}
		}
	}
	for id := range current {
		if !proven[id] {
			return ErrRecoveryEvidence
		}
	}
	return nil
}
