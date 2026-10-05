package cryptox

import ()

const MaxIssuerRecoveryRights = 1024
const MaxIssuerRecoveryPaths = 32
const MaxIssuerRecoveryNodes = 256

type IssuerRecoveryArchive struct {
	Kind                   string            `json:"kind"`
	Enrollment             *IssuerEnrollment `json:"enrollment,omitempty"`
	RecoveryEnrollmentHash string            `json:"recoveryEnrollmentHash,omitempty"`
}
type IssuerRecoveryAuthority struct {
	Grant                  SignedGrantWire `json:"grant"`
	ParentHash             string          `json:"parentHash"`
	OriginHash             string          `json:"originHash"`
	PreviousGrantHash      string          `json:"previousGrantHash"`
	RecoveryEnrollmentHash string          `json:"recoveryEnrollmentHash"`
}
type IssuerRecoveryProof struct {
	Profile           string                    `json:"profile"`
	AccountID         string                    `json:"accountId"`
	AccountGeneration string                    `json:"accountGeneration"`
	TrustRoot         TrustRoot                 `json:"trustRoot"`
	Initialization    OriginalInitialization    `json:"initialization"`
	Path              []IssuerRecoveryArchive   `json:"path"`
	Authorities       []IssuerRecoveryAuthority `json:"authorities"`
	Targets           []IssuerTarget            `json:"targets"`
	Origins           []SignedEnvironmentOrigin `json:"origins"`
	IdentityPaths     [][]IssuerRecoveryArchive `json:"identityPaths"`
}
type VerifiedIssuerRecoveryProof struct {
	graph    *VerifiedIssuerProofV2
	recovery *VerifiedRecoveryAuthority
}

func (v *VerifiedIssuerRecoveryProof) VerifyHistoricalGrant(s SignedGrantWire) error {
	if v == nil {
		return ErrInvalidWire
	}
	return v.graph.VerifyHistoricalGrant(s)
}
func (v *VerifiedIssuerRecoveryProof) VerifyDelegatedGrant(s SignedGrantWire, h string) error {
	if v == nil {
		return ErrInvalidWire
	}
	return v.graph.VerifyDelegatedGrant(s, h)
}
func (v *VerifiedIssuerRecoveryProof) VerifyTarget(s SignedGrantWire, d, ed, x string) error {
	if v == nil {
		return ErrInvalidWire
	}
	return v.graph.VerifyTarget(s, d, ed, x)
}
func (v *VerifiedIssuerRecoveryProof) IssuerBindings() []IssuerBinding {
	if v == nil {
		return nil
	}
	return v.graph.IssuerBindings()
}
func (v *VerifiedIssuerRecoveryProof) Authority(h string) (SignedGrantWire, bool) {
	if v == nil {
		return SignedGrantWire{}, false
	}
	return v.graph.Authority(h)
}
func (v *VerifiedIssuerRecoveryProof) InitialAuthorities() []SignedGrantWire {
	if v == nil {
		return nil
	}
	return v.recovery.InitialAuthorities()
}
