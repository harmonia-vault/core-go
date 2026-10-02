package cryptox

import (
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"strconv"
)

const EnvironmentOriginCapability = "issuer-origin-v1"

// EnvironmentRight 只包含控制面权限，绝不携带标签、变量或钥匙密文。
type EnvironmentRight struct {
	SubjectDeviceID           string `json:"subjectDeviceId"`
	SubjectSigningPublicKey   string `json:"subjectSigningPublicKey"`
	SubjectReceivingPublicKey string `json:"subjectReceivingPublicKey"`
	KeyVersion                string `json:"keyVersion"`
	GrantGeneration           string `json:"grantGeneration"`
	Role                      string `json:"role"`
	ExpiresAt                 string `json:"expiresAt"`
	GrantHash                 string `json:"grantHash"`
}
type EnvironmentOrigin struct {
	AccountID                string             `json:"accountId"`
	AccountGeneration        string             `json:"accountGeneration"`
	ActorDeviceID            string             `json:"actorDeviceId"`
	EnvironmentID            string             `json:"environmentId"`
	Operation                string             `json:"operation"`
	AuthorityEnvironmentID   string             `json:"authorityEnvironmentId"`
	AuthorityKeyVersion      string             `json:"authorityKeyVersion"`
	AuthorityGrantGeneration string             `json:"authorityGrantGeneration"`
	PreviousKeyVersion       string             `json:"previousKeyVersion"`
	KeyVersion               string             `json:"keyVersion"`
	ExpectedSequence         string             `json:"expectedSequence"`
	IdempotencyKey           string             `json:"idempotencyKey"`
	ChangeHash               string             `json:"changeHash"`
	AuthorityHash            string             `json:"authorityHash"`
	Before                   []EnvironmentRight `json:"before"`
	After                    []EnvironmentRight `json:"after"`
}
type SignedEnvironmentOrigin struct {
	Origin    EnvironmentOrigin `json:"origin"`
	Signature string            `json:"signature"`
}

// EnvironmentChangeV2 将原数据操作和最小来源证书关联；原 v1 编码保持不变。
type EnvironmentChangeV2 struct {
	Change    EnvironmentChange       `json:"change"`
	Signature string                  `json:"signature"`
	Origin    SignedEnvironmentOrigin `json:"origin"`
}

func rightRows(rights []EnvironmentRight) ([][]string, error) {
	if len(rights) > 256 {
		return nil, ErrInvalidWire
	}
	rows := make([][]string, 0, len(rights))
	for i, r := range rights {
		if validID(r.SubjectDeviceID) != nil || validatePublicPair(r.SubjectSigningPublicKey, r.SubjectReceivingPublicKey) != nil || validDecimal(r.KeyVersion, true) != nil || validDecimal(r.GrantGeneration, true) != nil || validDecimal(r.ExpiresAt, false) != nil || !issuerExpiryWithin(r.ExpiresAt, "0") || !tokenHashPattern.MatchString(r.GrantHash) || (r.Role != "ro" && r.Role != "rw" && r.Role != "admin") || (i > 0 && rights[i-1].SubjectDeviceID >= r.SubjectDeviceID) {
			return nil, ErrInvalidWire
		}
		rows = append(rows, []string{r.SubjectDeviceID, r.SubjectSigningPublicKey, r.SubjectReceivingPublicKey, r.KeyVersion, r.GrantGeneration, r.Role, r.ExpiresAt, r.GrantHash})
	}
	return rows, nil
}
func decimalSuccessor(previous, next string) bool {
	p, e := strconv.ParseUint(previous, 10, 64)
	if e != nil || p == ^uint64(0) {
		return false
	}
	return strconv.FormatUint(p+1, 10) == next
}
func (o EnvironmentOrigin) SigningBytes() ([]byte, error) {
	if o.Before == nil || o.After == nil {
		return nil, ErrInvalidWire
	}
	for _, id := range []string{o.AccountID, o.ActorDeviceID, o.EnvironmentID, o.AuthorityEnvironmentID, o.IdempotencyKey} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	for _, n := range []string{o.AccountGeneration, o.AuthorityKeyVersion, o.AuthorityGrantGeneration, o.KeyVersion} {
		if validDecimal(n, true) != nil {
			return nil, ErrInvalidWire
		}
	}
	if validDecimal(o.PreviousKeyVersion, false) != nil || validDecimal(o.ExpectedSequence, false) != nil || !tokenHashPattern.MatchString(o.ChangeHash) || !tokenHashPattern.MatchString(o.AuthorityHash) {
		return nil, ErrInvalidWire
	}
	seq, _ := strconv.ParseUint(o.ExpectedSequence, 10, 64)
	if seq > 9007199254740990 {
		return nil, ErrInvalidWire
	}
	before, e := rightRows(o.Before)
	if e != nil {
		return nil, e
	}
	after, e := rightRows(o.After)
	if e != nil {
		return nil, e
	}
	switch o.Operation {
	case "create":
		if o.PreviousKeyVersion != "0" || o.KeyVersion != "1" || len(o.Before) != 0 || len(o.After) != 1 {
			return nil, ErrInvalidWire
		}
		r := o.After[0]
		if r.SubjectDeviceID != o.ActorDeviceID || r.Role != "admin" || r.KeyVersion != "1" || r.GrantGeneration != "1" {
			return nil, ErrInvalidWire
		}
	case "rotate":
		if o.AuthorityEnvironmentID != o.EnvironmentID || o.AuthorityKeyVersion != o.PreviousKeyVersion || !decimalSuccessor(o.PreviousKeyVersion, o.KeyVersion) || len(o.Before) == 0 || len(o.Before) != len(o.After) {
			return nil, ErrInvalidWire
		}
		found := false
		for i, b := range o.Before {
			a := o.After[i]
			if b.KeyVersion != o.PreviousKeyVersion || a.KeyVersion != o.KeyVersion || !decimalSuccessor(b.GrantGeneration, a.GrantGeneration) || b.SubjectDeviceID != a.SubjectDeviceID || b.SubjectSigningPublicKey != a.SubjectSigningPublicKey || b.SubjectReceivingPublicKey != a.SubjectReceivingPublicKey || b.Role != a.Role || b.ExpiresAt != a.ExpiresAt {
				return nil, ErrInvalidWire
			}
			if b.SubjectDeviceID == o.ActorDeviceID {
				if b.Role != "admin" || b.GrantHash != o.AuthorityHash || b.GrantGeneration != o.AuthorityGrantGeneration {
					return nil, ErrInvalidWire
				}
				found = true
			}
		}
		if !found {
			return nil, ErrInvalidWire
		}
	default:
		return nil, ErrInvalidWire
	}
	return json.Marshal([]any{"harmonia/environment-origin/v1", o.AccountID, o.AccountGeneration, o.ActorDeviceID, o.EnvironmentID, o.Operation, o.AuthorityEnvironmentID, o.AuthorityKeyVersion, o.AuthorityGrantGeneration, o.PreviousKeyVersion, o.KeyVersion, o.ExpectedSequence, o.IdempotencyKey, o.ChangeHash, o.AuthorityHash, before, after})
}
func EnvironmentChangeReferenceHash(s SignedEnvironmentChange) (string, error) {
	b, e := s.Change.SigningBytes()
	if e != nil {
		return "", e
	}
	if _, e = DecodeBase64(s.Signature, 64, 64); e != nil {
		return "", e
	}
	return hashCanonical([]string{"harmonia/environment-change-ref/v1", EncodeBase64(b), s.Signature})
}
func EnvironmentOriginHash(s SignedEnvironmentOrigin) (string, error) {
	b, e := s.Origin.SigningBytes()
	if e != nil {
		return "", e
	}
	if _, e = DecodeBase64(s.Signature, 64, 64); e != nil {
		return "", e
	}
	return hashCanonical([]string{"harmonia/environment-origin-ref/v1", EncodeBase64(b), s.Signature})
}
func SignEnvironmentOrigin(o EnvironmentOrigin, key ed25519.PrivateKey) (SignedEnvironmentOrigin, error) {
	b, e := o.SigningBytes()
	if e != nil {
		return SignedEnvironmentOrigin{}, e
	}
	sig, e := sign(key, b)
	return SignedEnvironmentOrigin{o, sig}, e
}
func VerifyEnvironmentOrigin(s SignedEnvironmentOrigin, key ed25519.PublicKey) error {
	b, e := s.Origin.SigningBytes()
	if e != nil {
		return e
	}
	return verify(key, b, s.Signature)
}
func EnvironmentRights(grants []SignedGrantWire) ([]EnvironmentRight, error) {
	out := make([]EnvironmentRight, 0, len(grants))
	for _, s := range grants {
		g := s.Grant
		h, e := IssuerAuthorityHash(s)
		if e != nil {
			return nil, e
		}
		out = append(out, EnvironmentRight{g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey, g.KeyVersion, g.GrantGeneration, g.Role, g.ExpiresAt, h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SubjectDeviceID < out[j].SubjectDeviceID })
	if _, e := rightRows(out); e != nil {
		return nil, e
	}
	return out, nil
}
func sameRights(a, b []EnvironmentRight) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VerifyEnvironmentOriginChange 的 before 必须来自已验证/已接受的精确旧快照，
// 不能以原包自己声称的 Before 替代。服务端仍须在接受事务内重查当前有效集合。
func VerifyEnvironmentOriginChange(change SignedEnvironmentChange, s SignedEnvironmentOrigin, authority SignedGrantWire, before []SignedGrantWire, key ed25519.PublicKey) error {
	if e := VerifyEnvironmentChange(change, key); e != nil {
		return e
	}
	if e := VerifyEnvironmentOrigin(s, key); e != nil {
		return e
	}
	c, o, g := change.Change, s.Origin, authority.Grant
	ch, e := EnvironmentChangeReferenceHash(change)
	if e != nil {
		return e
	}
	ah, e := IssuerAuthorityHash(authority)
	if e != nil {
		return e
	}
	if o.AccountID != c.AccountID || o.AccountGeneration != c.AccountGeneration || o.ActorDeviceID != c.DeviceID || o.EnvironmentID != c.EnvironmentID || o.Operation != c.Operation || o.AuthorityEnvironmentID != c.AuthorityEnvironmentID || o.AuthorityKeyVersion != c.AuthorityKeyVersion || o.AuthorityGrantGeneration != c.AuthorityGrantGeneration || o.PreviousKeyVersion != c.PreviousKeyVersion || o.KeyVersion != c.KeyVersion || o.ExpectedSequence != c.ExpectedSequence || o.IdempotencyKey != c.IdempotencyKey || o.ChangeHash != ch || o.AuthorityHash != ah || g.AccountID != o.AccountID || g.AccountGeneration != o.AccountGeneration || g.SubjectDeviceID != o.ActorDeviceID || g.EnvironmentID != o.AuthorityEnvironmentID || g.KeyVersion != o.AuthorityKeyVersion || g.GrantGeneration != o.AuthorityGrantGeneration || g.Role != "admin" || g.SubjectSigningPublicKey != EncodeBase64(key) {
		return ErrInvalidSignature
	}
	br, e := EnvironmentRights(before)
	if e != nil {
		return e
	}
	ar, e := EnvironmentRights(c.Grants)
	if e != nil {
		return e
	}
	if !sameRights(br, o.Before) || !sameRights(ar, o.After) {
		return ErrInvalidWire
	}
	for _, r := range before {
		if r.Grant.AccountID != o.AccountID || r.Grant.AccountGeneration != o.AccountGeneration || r.Grant.EnvironmentID != o.EnvironmentID || r.Grant.KeyVersion != o.PreviousKeyVersion {
			return ErrInvalidWire
		}
	}
	for _, r := range c.Grants {
		if r.Grant.AccountID != o.AccountID || r.Grant.AccountGeneration != o.AccountGeneration || r.Grant.EnvironmentID != o.EnvironmentID || r.Grant.KeyVersion != o.KeyVersion || r.Grant.IssuerDeviceID != o.ActorDeviceID {
			return ErrInvalidWire
		}
		if e := VerifyGrant(r.SignedGrant(), key); e != nil {
			return e
		}
	}
	if o.Operation == "create" && (!issuerExpiryWithin(o.After[0].ExpiresAt, g.ExpiresAt) || o.After[0].SubjectSigningPublicKey != g.SubjectSigningPublicKey || o.After[0].SubjectReceivingPublicKey != g.SubjectReceivingPublicKey) {
		return ErrInvalidWire
	}
	return nil
}
func NewEnvironmentChangeV2(change SignedEnvironmentChange, authority SignedGrantWire, before []SignedGrantWire, key ed25519.PrivateKey) (EnvironmentChangeV2, error) {
	if len(key) != ed25519.PrivateKeySize {
		return EnvironmentChangeV2{}, ErrInvalidWire
	}
	c := change.Change
	ch, e := EnvironmentChangeReferenceHash(change)
	if e != nil {
		return EnvironmentChangeV2{}, e
	}
	ah, e := IssuerAuthorityHash(authority)
	if e != nil {
		return EnvironmentChangeV2{}, e
	}
	br, e := EnvironmentRights(before)
	if e != nil {
		return EnvironmentChangeV2{}, e
	}
	ar, e := EnvironmentRights(c.Grants)
	if e != nil {
		return EnvironmentChangeV2{}, e
	}
	o := EnvironmentOrigin{c.AccountID, c.AccountGeneration, c.DeviceID, c.EnvironmentID, c.Operation, c.AuthorityEnvironmentID, c.AuthorityKeyVersion, c.AuthorityGrantGeneration, c.PreviousKeyVersion, c.KeyVersion, c.ExpectedSequence, c.IdempotencyKey, ch, ah, br, ar}
	s, e := SignEnvironmentOrigin(o, key)
	if e != nil {
		return EnvironmentChangeV2{}, e
	}
	if e = VerifyEnvironmentOriginChange(change, s, authority, before, key.Public().(ed25519.PublicKey)); e != nil {
		return EnvironmentChangeV2{}, e
	}
	return EnvironmentChangeV2{c, change.Signature, s}, nil
}

// EnvironmentSubmissionHash 冻结原数据包与原来源包，不能只查旧 inner change 摘要。
func EnvironmentSubmissionHash(p EnvironmentChangeV2) (string, error) {
	cb, e := p.Change.SigningBytes()
	if e != nil {
		return "", e
	}
	ob, e := p.Origin.Origin.SigningBytes()
	if e != nil {
		return "", e
	}
	for _, s := range []string{p.Signature, p.Origin.Signature} {
		if _, e = DecodeBase64(s, 64, 64); e != nil {
			return "", e
		}
	}
	return hashCanonical([]string{"harmonia/environment-submission/v2", EncodeBase64(cb), p.Signature, EncodeBase64(ob), p.Origin.Signature})
}
