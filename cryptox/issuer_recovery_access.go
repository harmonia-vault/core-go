package cryptox

import (
	"crypto/ed25519"
)

type VerifiedIssuerIdentity struct {
	DeviceID           string
	SigningPublicKey   string
	ReceivingPublicKey string
}

func (v *VerifiedIssuerRecoveryProof) VerifiedIdentity(deviceID string) (VerifiedIssuerIdentity, bool) {
	if v == nil || v.graph == nil {
		return VerifiedIssuerIdentity{}, false
	}
	id, ok := v.graph.identities[deviceID]
	if !ok {
		return VerifiedIssuerIdentity{}, false
	}
	return VerifiedIssuerIdentity{id.id, id.signing, id.receiving}, true
}

func (v *VerifiedIssuerRecoveryProof) VerifyEnvironmentOriginEvent(change SignedEnvironmentChange, origin SignedEnvironmentOrigin, authority SignedGrantWire) error {
	if v == nil || v.graph == nil {
		return ErrInvalidWire
	}
	return v.graph.VerifyEnvironmentOriginEvent(change, origin, authority)
}

func (v *VerifiedIssuerRecoveryProof) VerifyHistoricalMutationSource(s SignedMutationWire, authority SignedGrantWire) error {
	if v == nil || v.graph == nil {
		return ErrInvalidWire
	}
	if e := v.VerifyHistoricalGrant(authority); e != nil {
		return e
	}
	m, g := s.Mutation, authority.Grant
	if m.AccountID != v.graph.accountID || m.AccountGeneration != v.graph.accountGeneration || g.AccountID != m.AccountID || g.AccountGeneration != m.AccountGeneration || g.SubjectDeviceID != m.DeviceID || g.EnvironmentID != m.EnvironmentID || g.KeyVersion != m.KeyVersion || g.GrantGeneration != m.GrantGeneration || (g.Role != "rw" && g.Role != "admin") {
		return ErrInvalidSignature
	}
	key, e := DecodeBase64(g.SubjectSigningPublicKey, 32, 32)
	if e != nil {
		return e
	}
	return VerifyMutation(s.SignedMutation(), ed25519.PublicKey(key))
}

type IssuerRecoveryCheckpoint struct {
	AccountID          string
	AccountGeneration  string
	RecoveryGeneration string
	SigningPublicKey   string
	ReceivingPublicKey string
	TransitionHead     string
	AcceptedSequence   uint64
}

func (v *VerifiedIssuerRecoveryProof) RecoveryCheckpoint() (IssuerRecoveryCheckpoint, error) {
	if v == nil || v.recovery == nil {
		return IssuerRecoveryCheckpoint{}, ErrInvalidWire
	}
	a := v.recovery
	return IssuerRecoveryCheckpoint{a.pin.AccountID, a.pin.AccountGeneration, a.Generation(), a.SigningPublicKey(), a.ReceivingPublicKey(), a.HeadHash(), a.sequence}, nil
}
