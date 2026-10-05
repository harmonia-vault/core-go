package cryptox

import (
	"sort"
)

const MaxIssuerOrigins = 128
const MaxIssuerProofV2Bytes = 2 << 20

type IssuerAuthorityV2 struct {
	Grant             SignedGrantWire `json:"grant"`
	ParentHash        string          `json:"parentHash"`
	OriginHash        string          `json:"originHash"`
	PreviousGrantHash string          `json:"previousGrantHash"`
}
type VerifiedIssuerProofV2 struct {
	accountID, accountGeneration string
	identities                   map[string]issuerIdentity
	authorities                  map[string]IssuerAuthorityV2
	origins                      map[string]SignedEnvironmentOrigin
	targets                      map[string]string
	genesis                      []SignedGrantWire
}

func (v *VerifiedIssuerProofV2) IssuerBindings() []IssuerBinding {
	out := make([]IssuerBinding, 0, len(v.authorities))
	for h, a := range v.authorities {
		g := a.Grant.Grant
		out = append(out, IssuerBinding{g.EnvironmentID, g.KeyVersion, g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey, h})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.EnvironmentID != b.EnvironmentID {
			return a.EnvironmentID < b.EnvironmentID
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		return a.AuthorityHash < b.AuthorityHash
	})
	return out
}
func (v *VerifiedIssuerProofV2) VerifyDelegatedGrant(s SignedGrantWire, h string) error {
	a, ok := v.authorities[h]
	if !ok {
		return ErrInvalidSignature
	}
	p, g := a.Grant.Grant, s.Grant
	if identity, known := v.identities[g.SubjectDeviceID]; known && !issuerIdentityMatches(identity, g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey) {
		return ErrInvalidSignature
	}
	if p.Role != "admin" || g.AccountID != v.accountID || g.AccountGeneration != v.accountGeneration || g.EnvironmentID != p.EnvironmentID || g.KeyVersion != p.KeyVersion || g.IssuerDeviceID != p.SubjectDeviceID || validatePublicPair(g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey) != nil || (g.Role != "none" && !issuerExpiryWithin(g.ExpiresAt, p.ExpiresAt)) {
		return ErrInvalidSignature
	}
	key, _ := DecodeBase64(p.SubjectSigningPublicKey, 32, 32)
	return VerifyGrant(s.SignedGrant(), key)
}
func (v *VerifiedIssuerProofV2) VerifyHistoricalGrant(s SignedGrantWire) error {
	identity, known := v.identities[s.Grant.SubjectDeviceID]
	if !known || !issuerIdentityMatches(identity, s.Grant.SubjectDeviceID, s.Grant.SubjectSigningPublicKey, s.Grant.SubjectReceivingPublicKey) {
		return ErrInvalidSignature
	}
	h, e := IssuerAuthorityHash(s)
	if e != nil {
		return e
	}
	if _, ok := v.authorities[h]; ok {
		return nil
	}
	for h := range v.authorities {
		if v.VerifyDelegatedGrant(s, h) == nil {
			return nil
		}
	}
	return ErrInvalidSignature
}
func (v *VerifiedIssuerProofV2) VerifyTarget(s SignedGrantWire, device, signing, receiving string) error {
	h, e := IssuerAuthorityHash(s)
	if e != nil {
		return e
	}
	g := s.Grant
	if v.targets[g.EnvironmentID] != h || g.SubjectDeviceID != device || g.SubjectSigningPublicKey != signing || g.SubjectReceivingPublicKey != receiving {
		return ErrInvalidSignature
	}
	return v.VerifyHistoricalGrant(s)
}
func (v *VerifiedIssuerProofV2) Authority(h string) (SignedGrantWire, bool) {
	a, ok := v.authorities[h]
	return a.Grant, ok
}

func (v *VerifiedIssuerProofV2) InitialAuthorities() []SignedGrantWire {
	return append([]SignedGrantWire(nil), v.genesis...)
}
func (v *VerifiedIssuerProofV2) VerifyEnvironmentOriginEvent(change SignedEnvironmentChange, origin SignedEnvironmentOrigin, authority SignedGrantWire) error {
	h, e := EnvironmentOriginHash(origin)
	if e != nil {
		return e
	}
	if _, known := v.origins[h]; !known {
		return ErrInvalidSignature
	}
	o := origin.Origin
	actor, ok := v.identities[o.ActorDeviceID]
	if !ok {
		return ErrInvalidSignature
	}
	before := make([]SignedGrantWire, 0, len(o.Before))
	for _, r := range o.Before {
		a, ok := v.authorities[r.GrantHash]
		if !ok {
			return ErrInvalidSignature
		}
		before = append(before, a.Grant)
	}
	key, e := DecodeBase64(actor.signing, 32, 32)
	if e != nil {
		return e
	}
	return VerifyEnvironmentOriginChange(change, origin, authority, before, key)
}

const MaxIssuerRightsV2 = 512
