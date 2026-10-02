package cryptox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"time"
)

const (
	IssuerProofV2Profile   = "harmonia/issuer-proof/v2"
	MaxIssuerProofV2Bytes  = 1 << 20
	MaxIssuerRightsV2      = 512
	MaxIssuerOrigins       = 128
	MaxIssuerIdentityPaths = 16
	MaxIssuerArchiveNodes  = 128
)

type IssuerAuthorityV2 struct {
	Grant             SignedGrantWire `json:"grant"`
	ParentHash        string          `json:"parentHash"`
	OriginHash        string          `json:"originHash"`
	PreviousGrantHash string          `json:"previousGrantHash"`
}
type IssuerProofV2 struct {
	Profile           string                    `json:"profile"`
	AccountID         string                    `json:"accountId"`
	AccountGeneration string                    `json:"accountGeneration"`
	TrustRoot         TrustRoot                 `json:"trustRoot"`
	Path              []IssuerEnrollment        `json:"path"`
	Authorities       []IssuerAuthorityV2       `json:"authorities"`
	Targets           []IssuerTarget            `json:"targets"`
	Origins           []SignedEnvironmentOrigin `json:"origins"`
	IdentityPaths     [][]IssuerEnrollment      `json:"identityPaths"`
}
type EnrollmentCertificateV3 struct {
	EnrollmentCertificate
	IssuerProofHash string `json:"issuerProofHash"`
}
type EnrollmentApprovalV3 struct {
	CertificateVersion string            `json:"certificateVersion"`
	Context            EnrollmentContext `json:"context"`
	PairingProfile     string            `json:"pairingProfile"`
	TranscriptHash     string            `json:"transcriptHash"`
	Grants             []SignedGrantWire `json:"grants"`
	IssuerProof        IssuerProofV2     `json:"issuerProof"`
	ApproverSignature  string            `json:"approverSignature"`
	InitiatorSignature string            `json:"initiatorSignature,omitempty"`
}

func (c EnrollmentCertificateV3) SigningBytes() ([]byte, error) {
	b, e := (EnrollmentCertificateV2{c.EnrollmentCertificate, c.IssuerProofHash}).SigningBytes()
	if e != nil {
		return nil, e
	}
	var f []string
	if e = json.Unmarshal(b, &f); e != nil {
		return nil, e
	}
	f[0] = "harmonia/device-enrollment/v3"
	return json.Marshal(f)
}
func SignEnrollmentCertificateV3(c EnrollmentCertificateV3, key ed25519.PrivateKey) (string, error) {
	b, e := c.SigningBytes()
	if e != nil {
		return "", e
	}
	if len(key) != ed25519.PrivateKeySize {
		return "", ErrInvalidWire
	}
	pub := EncodeBase64(key.Public().(ed25519.PublicKey))
	if pub != c.InitiatorSigningPublicKey && pub != c.ApproverSigningPublicKey {
		return "", ErrInvalidWire
	}
	return sign(key, b)
}
func VerifyEnrollmentCertificateV3(c EnrollmentCertificateV3, sig string, key ed25519.PublicKey) error {
	b, e := c.SigningBytes()
	if e != nil {
		return e
	}
	pub := EncodeBase64(key)
	if pub != c.InitiatorSigningPublicKey && pub != c.ApproverSigningPublicKey {
		return ErrInvalidSignature
	}
	return verify(key, b, sig)
}
func issuerArchiveBytesV2(n IssuerEnrollment) ([]byte, error) {
	if n.CertificateVersion == "3" {
		c, e := n.Approval.Certificate()
		if e != nil {
			return nil, e
		}
		return (EnrollmentCertificateV3{c, n.IssuerProofHash}).SigningBytes()
	}
	return n.CertificateBytes()
}
func issuerPathRowsV2(path []IssuerEnrollment) ([][]string, error) {
	if len(path) > MaxIssuerProofPath {
		return nil, ErrInvalidWire
	}
	rows := make([][]string, 0, len(path))
	for _, n := range path {
		b, e := issuerArchiveBytesV2(n)
		if e != nil {
			return nil, e
		}
		for _, s := range []string{n.Approval.ApproverSignature, n.Approval.InitiatorSignature} {
			if _, e = DecodeBase64(s, 64, 64); e != nil {
				return nil, e
			}
		}
		rows = append(rows, []string{n.CertificateVersion, EncodeBase64(b), n.Approval.ApproverSignature, n.Approval.InitiatorSignature})
	}
	return rows, nil
}
func (p IssuerProofV2) CanonicalBytes() ([]byte, error) {
	if p.Path == nil || p.Authorities == nil || p.Targets == nil || p.Origins == nil || p.IdentityPaths == nil {
		return nil, ErrInvalidWire
	}
	if p.Profile != IssuerProofV2Profile || validID(p.AccountID) != nil || validDecimal(p.AccountGeneration, true) != nil || len(p.Authorities) < 1 || len(p.Authorities) > MaxIssuerRightsV2 || len(p.Targets) > 256 || len(p.Origins) > MaxIssuerOrigins || len(p.IdentityPaths) > MaxIssuerIdentityPaths {
		return nil, ErrInvalidWire
	}
	root, e := p.TrustRoot.SigningBytes(p.AccountID, p.AccountGeneration)
	if e != nil {
		return nil, e
	}
	if _, e = DecodeBase64(p.TrustRoot.Signature, 64, 64); e != nil {
		return nil, e
	}
	paths, e := issuerPathRowsV2(p.Path)
	if e != nil {
		return nil, e
	}
	type branch struct {
		rows    [][]string
		encoded string
	}
	branches := make([]branch, 0, len(p.IdentityPaths))
	total := len(p.Path)
	for _, path := range p.IdentityPaths {
		if len(path) == 0 {
			return nil, ErrInvalidWire
		}
		total += len(path)
		r, e := issuerPathRowsV2(path)
		if e != nil {
			return nil, e
		}
		b, _ := json.Marshal(r)
		branches = append(branches, branch{r, string(b)})
	}
	if total > MaxIssuerArchiveNodes {
		return nil, ErrInvalidWire
	}
	sort.Slice(branches, func(i, j int) bool { return branches[i].encoded < branches[j].encoded })
	branchRows := make([][][]string, 0, len(branches))
	for i, b := range branches {
		if i > 0 && branches[i-1].encoded == b.encoded {
			return nil, ErrInvalidWire
		}
		branchRows = append(branchRows, b.rows)
	}
	as := append([]IssuerAuthorityV2(nil), p.Authorities...)
	sort.Slice(as, func(i, j int) bool {
		a, b := as[i].Grant.Grant, as[j].Grant.Grant
		if a.EnvironmentID != b.EnvironmentID {
			return a.EnvironmentID < b.EnvironmentID
		}
		if a.SubjectDeviceID != b.SubjectDeviceID {
			return a.SubjectDeviceID < b.SubjectDeviceID
		}
		x, _ := strconv.ParseUint(a.GrantGeneration, 10, 64)
		y, _ := strconv.ParseUint(b.GrantGeneration, 10, 64)
		return x < y
	})
	rows := make([][]string, 0, len(as))
	seen := map[string]bool{}
	for _, a := range as {
		g := a.Grant.Grant
		b, e := g.SigningBytes()
		if e != nil {
			return nil, e
		}
		if g.Role != "ro" && g.Role != "rw" && g.Role != "admin" {
			return nil, ErrInvalidWire
		}
		for _, h := range []string{a.ParentHash, a.OriginHash, a.PreviousGrantHash} {
			if h != "" && !tokenHashPattern.MatchString(h) {
				return nil, ErrInvalidWire
			}
		}
		if _, e = IssuerAuthorityHash(a.Grant); e != nil {
			return nil, e
		}
		id := g.EnvironmentID + "/" + g.SubjectDeviceID + "/" + g.GrantGeneration
		if seen[id] {
			return nil, ErrInvalidWire
		}
		seen[id] = true
		rows = append(rows, []string{g.EnvironmentID, g.SubjectDeviceID, g.GrantGeneration, EncodeBase64(b), a.Grant.Signature, a.ParentHash, a.OriginHash, a.PreviousGrantHash})
	}
	ts := append([]IssuerTarget(nil), p.Targets...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].EnvironmentID < ts[j].EnvironmentID })
	targets := make([][]string, 0, len(ts))
	for i, t := range ts {
		if validID(t.EnvironmentID) != nil || !tokenHashPattern.MatchString(t.AuthorityHash) || (i > 0 && ts[i-1].EnvironmentID == t.EnvironmentID) {
			return nil, ErrInvalidWire
		}
		targets = append(targets, []string{t.EnvironmentID, t.AuthorityHash})
	}
	origins := make([][]string, 0, len(p.Origins))
	for _, s := range p.Origins {
		h, e := EnvironmentOriginHash(s)
		if e != nil {
			return nil, e
		}
		b, _ := s.Origin.SigningBytes()
		origins = append(origins, []string{h, EncodeBase64(b), s.Signature})
	}
	sort.Slice(origins, func(i, j int) bool { return origins[i][0] < origins[j][0] })
	for i := 1; i < len(origins); i++ {
		if origins[i-1][0] == origins[i][0] {
			return nil, ErrInvalidWire
		}
	}
	b, e := json.Marshal([]any{IssuerProofV2Profile, p.AccountID, p.AccountGeneration, []string{EncodeBase64(root), p.TrustRoot.Signature}, paths, rows, targets, origins, branchRows})
	if e != nil || len(b) > MaxIssuerProofV2Bytes {
		return nil, ErrInvalidWire
	}
	return b, nil
}
func (p IssuerProofV2) Hash() (string, error) {
	b, e := p.CanonicalBytes()
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func (a EnrollmentApprovalV3) Certificate() (EnrollmentCertificateV3, error) {
	if a.CertificateVersion != "3" || a.IssuerProof.AccountID != a.Context.AccountID || a.IssuerProof.AccountGeneration != a.Context.AccountGeneration {
		return EnrollmentCertificateV3{}, ErrInvalidWire
	}
	base, e := (EnrollmentApproval{a.Context, a.PairingProfile, a.TranscriptHash, a.Grants, a.ApproverSignature, a.InitiatorSignature}).Certificate()
	if e != nil {
		return EnrollmentCertificateV3{}, e
	}
	h, e := a.IssuerProof.Hash()
	if e != nil {
		return EnrollmentCertificateV3{}, e
	}
	return EnrollmentCertificateV3{base, h}, nil
}
func DecodeEnrollmentApprovalV3(data []byte) (EnrollmentApprovalV3, error) {
	if e := ValidateStrictJSON(data, MaxIssuerProofV2Bytes); e != nil {
		return EnrollmentApprovalV3{}, e
	}
	if len(data) == 0 || len(data) > MaxIssuerProofV2Bytes {
		return EnrollmentApprovalV3{}, ErrInvalidWire
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var a EnrollmentApprovalV3
	if e := d.Decode(&a); e != nil {
		return a, e
	}
	var rest any
	if e := d.Decode(&rest); !errors.Is(e, io.EOF) {
		return a, ErrInvalidWire
	}
	_, e := a.Certificate()
	return a, e
}

// VerifiedIssuerProofV2 固定逐环境历史来源。它没有当前权限字段或恢复信任输出。
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

// VerifyIssuerEvidenceV2 仅接受独立已有根 pin；不得从传入的服务器 proof 生成该 pin。
func VerifyIssuerEvidenceV2(pin PinnedIssuerRoot, p IssuerProofV2, initial ...SignedGrantWire) (*VerifiedIssuerProofV2, error) {
	if len(initial) == 0 || len(initial) > MaxIssuerRightsV2 {
		return nil, ErrInvalidWire
	}
	genesis := map[string]SignedGrantWire{}
	for _, s := range initial {
		g := s.Grant
		if g.AccountID != pin.AccountID || g.AccountGeneration != pin.AccountGeneration || g.IssuerDeviceID != pin.DeviceID || g.SubjectDeviceID != pin.DeviceID || g.SubjectSigningPublicKey != pin.SigningPublicKey || g.SubjectReceivingPublicKey != pin.ReceivingPublicKey || g.Role != "admin" || g.KeyVersion != "1" || g.GrantGeneration != "1" || g.ExpiresAt != "0" {
			return nil, ErrInvalidWire
		}
		key, e := DecodeBase64(pin.SigningPublicKey, 32, 32)
		if e != nil {
			return nil, e
		}
		if e = VerifyGrant(s.SignedGrant(), key); e != nil {
			return nil, e
		}
		h, e := IssuerAuthorityHash(s)
		if e != nil {
			return nil, e
		}
		if _, ok := genesis[h]; ok {
			return nil, ErrInvalidWire
		}
		genesis[h] = s
	}
	return verifyIssuerEvidenceV2(pin, p, genesis)
}
func proofGenesisV2(p IssuerProofV2) []SignedGrantWire {
	out := []SignedGrantWire{}
	for _, a := range p.Authorities {
		if a.ParentHash == "" && a.OriginHash == "" && a.PreviousGrantHash == "" {
			out = append(out, a.Grant)
		}
	}
	return out
}
func (v *VerifiedIssuerProofV2) InitialAuthorities() []SignedGrantWire {
	return append([]SignedGrantWire(nil), v.genesis...)
}
func verifyIssuerEvidenceV2(pin PinnedIssuerRoot, p IssuerProofV2, genesis map[string]SignedGrantWire) (*VerifiedIssuerProofV2, error) {
	if pin.AccountID != p.AccountID || pin.AccountGeneration != p.AccountGeneration || pin.DeviceID != p.TrustRoot.RootDeviceID || pin.SigningPublicKey != p.TrustRoot.RootSigningPublicKey || pin.ReceivingPublicKey != p.TrustRoot.RootReceivingPublicKey {
		return nil, ErrInvalidSignature
	}
	if _, e := p.CanonicalBytes(); e != nil {
		return nil, e
	}
	root := issuerIdentity{pin.DeviceID, pin.SigningPublicKey, pin.ReceivingPublicKey}
	recoverKey, e := DecodeBase64(p.TrustRoot.RecoverySigningPublicKey, 32, 32)
	if e != nil {
		return nil, e
	}
	if e = VerifyTrustRoot(p.AccountID, p.AccountGeneration, p.TrustRoot, recoverKey); e != nil {
		return nil, e
	}
	v := &VerifiedIssuerProofV2{p.AccountID, p.AccountGeneration, map[string]issuerIdentity{}, map[string]IssuerAuthorityV2{}, map[string]SignedEnvironmentOrigin{}, map[string]string{}, nil}
	used := map[string]string{p.TrustRoot.RecoverySigningPublicKey: "recovery", p.TrustRoot.RecoveryReceivingPublicKey: "recovery"}
	add := func(id issuerIdentity) error {
		if validatePublicPair(id.signing, id.receiving) != nil {
			return ErrInvalidWire
		}
		if old, ok := v.identities[id.id]; ok {
			if old != id {
				return ErrInvalidWire
			}
			return nil
		}
		for _, pub := range []string{id.signing, id.receiving} {
			if _, ok := used[pub]; ok {
				return ErrInvalidWire
			}
		}
		v.identities[id.id] = id
		used[id.signing] = id.id
		used[id.receiving] = id.id
		return nil
	}
	if e = add(root); e != nil {
		return nil, e
	}
	archived := map[string]string{}
	allPaths := append([][]IssuerEnrollment{p.Path}, p.IdentityPaths...)
	for _, path := range allPaths {
		current := root
		pathIDs := map[string]bool{root.id: true}
		for _, n := range path {
			c := n.Approval.Context
			if c.AccountID != p.AccountID || c.AccountGeneration != p.AccountGeneration || issuerHistoricalContext(c) != nil || !issuerIdentityMatches(current, c.ApproverDeviceID, c.ApproverSigningPublicKey, c.ApproverReceivingPublicKey) || pathIDs[c.InitiatorDeviceID] {
				return nil, ErrInvalidWire
			}
			b, e := issuerArchiveBytesV2(n)
			if e != nil {
				return nil, e
			}
			nodeHash, e := hashCanonical([]string{EncodeBase64(b), n.Approval.ApproverSignature, n.Approval.InitiatorSignature})
			if e != nil {
				return nil, e
			}
			if old, ok := archived[c.InitiatorDeviceID]; ok && old != nodeHash {
				return nil, ErrInvalidWire
			}
			archived[c.InitiatorDeviceID] = nodeHash
			parentKey, _ := DecodeBase64(current.signing, 32, 32)
			if e = verify(parentKey, b, n.Approval.ApproverSignature); e != nil {
				return nil, e
			}
			child := issuerIdentity{c.InitiatorDeviceID, c.InitiatorSigningPublicKey, c.InitiatorReceivingPublicKey}
			if e = add(child); e != nil {
				return nil, e
			}
			childKey, _ := DecodeBase64(child.signing, 32, 32)
			if e = verify(childKey, b, n.Approval.InitiatorSignature); e != nil {
				return nil, e
			}
			base, e := n.Approval.Certificate()
			if e != nil {
				return nil, e
			}
			if e = VerifyEnrollmentGrants(base, n.Approval.Grants, parentKey); e != nil {
				return nil, e
			}
			pathIDs[child.id] = true
			current = child
		}
	}
	seenGen, seenOp := map[string]string{}, map[string]string{}
	checkUnique := func(s SignedGrantWire) error {
		g := s.Grant
		h, e := IssuerAuthorityHash(s)
		if e != nil {
			return e
		}
		if g.AccountID != p.AccountID || g.AccountGeneration != p.AccountGeneration {
			return ErrInvalidWire
		}
		for id, table := range map[string]map[string]string{"gen/" + g.EnvironmentID + "/" + g.SubjectDeviceID + "/" + g.GrantGeneration: seenGen, "op/" + g.IssuerDeviceID + "/" + g.IdempotencyKey: seenOp} {
			if old, ok := table[id]; ok && old != h {
				return ErrInvalidWire
			}
			table[id] = h
		}
		return nil
	}
	for _, path := range allPaths {
		for _, n := range path {
			for _, g := range n.Approval.Grants {
				if e = checkUnique(g); e != nil {
					return nil, e
				}
			}
		}
	}
	for _, a := range p.Authorities {
		g := a.Grant.Grant
		if e = checkUnique(a.Grant); e != nil {
			return nil, e
		}
		sub, ok := v.identities[g.SubjectDeviceID]
		issuer, iok := v.identities[g.IssuerDeviceID]
		if !ok || !iok || !issuerIdentityMatches(sub, g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey) || !issuerExpiryWithin(g.ExpiresAt, "0") {
			return nil, ErrInvalidWire
		}
		key, _ := DecodeBase64(issuer.signing, 32, 32)
		if e = VerifyGrant(a.Grant.SignedGrant(), key); e != nil {
			return nil, e
		}
		h, _ := IssuerAuthorityHash(a.Grant)
		if _, ok = v.authorities[h]; ok {
			return nil, ErrInvalidWire
		}
		v.authorities[h] = a
	}
	for _, s := range p.Origins {
		o := s.Origin
		if o.AccountID != p.AccountID || o.AccountGeneration != p.AccountGeneration {
			return nil, ErrInvalidWire
		}
		actor, ok := v.identities[o.ActorDeviceID]
		if !ok {
			return nil, ErrInvalidSignature
		}
		key, _ := DecodeBase64(actor.signing, 32, 32)
		if e = VerifyEnvironmentOrigin(s, key); e != nil {
			return nil, e
		}
		h, _ := EnvironmentOriginHash(s)
		v.origins[h] = s
	}
	states := map[string]uint8{}
	originStates := map[string]uint8{}
	var checkRight func(string) error
	var checkOrigin func(string) error
	match := func(r EnvironmentRight, g SignedGrantWire, o EnvironmentOrigin, version string) bool {
		rs, e := EnvironmentRights([]SignedGrantWire{g})
		return e == nil && rs[0] == r && g.Grant.AccountID == o.AccountID && g.Grant.AccountGeneration == o.AccountGeneration && g.Grant.EnvironmentID == o.EnvironmentID && g.Grant.KeyVersion == version
	}
	checkOrigin = func(h string) error {
		if originStates[h] == 2 {
			return nil
		}
		if originStates[h] == 1 {
			return ErrInvalidWire
		}
		s, ok := v.origins[h]
		if !ok {
			return ErrInvalidWire
		}
		originStates[h] = 1
		o := s.Origin
		if e := checkRight(o.AuthorityHash); e != nil {
			return e
		}
		actor := v.authorities[o.AuthorityHash].Grant.Grant
		if actor.Role != "admin" || actor.SubjectDeviceID != o.ActorDeviceID || actor.EnvironmentID != o.AuthorityEnvironmentID || actor.KeyVersion != o.AuthorityKeyVersion || actor.GrantGeneration != o.AuthorityGrantGeneration {
			return ErrInvalidWire
		}
		for _, r := range o.Before {
			if e := checkRight(r.GrantHash); e != nil {
				return e
			}
			a, ok := v.authorities[r.GrantHash]
			if !ok || !match(r, a.Grant, o, o.PreviousKeyVersion) {
				return ErrInvalidWire
			}
		}
		for i, r := range o.After {
			a, ok := v.authorities[r.GrantHash]
			if !ok || !match(r, a.Grant, o, o.KeyVersion) || a.Grant.Grant.IssuerDeviceID != o.ActorDeviceID || a.ParentHash != o.AuthorityHash || a.OriginHash != h {
				return ErrInvalidWire
			}
			if o.Operation == "create" {
				if a.PreviousGrantHash != "" || !issuerExpiryWithin(r.ExpiresAt, actor.ExpiresAt) || r.SubjectSigningPublicKey != actor.SubjectSigningPublicKey || r.SubjectReceivingPublicKey != actor.SubjectReceivingPublicKey {
					return ErrInvalidWire
				}
			} else if a.PreviousGrantHash != o.Before[i].GrantHash {
				return ErrInvalidWire
			}
		}
		originStates[h] = 2
		return nil
	}
	checkRight = func(h string) error {
		if states[h] == 2 {
			return nil
		}
		if states[h] == 1 {
			return ErrInvalidWire
		}
		a, ok := v.authorities[h]
		if !ok {
			return ErrInvalidWire
		}
		states[h] = 1
		g := a.Grant.Grant
		switch {
		case a.OriginHash != "":
			if a.ParentHash == "" {
				return ErrInvalidWire
			}
			if e := checkOrigin(a.OriginHash); e != nil {
				return e
			}
			o := v.origins[a.OriginHash].Origin
			found := false
			for _, r := range o.After {
				if r.GrantHash == h {
					found = true
				}
			}
			if !found {
				return ErrInvalidWire
			}
		case a.ParentHash == "":
			if _, anchored := genesis[h]; !anchored {
				return ErrInvalidSignature
			}
			v.genesis = append(v.genesis, a.Grant)
			if a.PreviousGrantHash != "" || g.Role != "admin" || g.KeyVersion != "1" || g.GrantGeneration != "1" || g.ExpiresAt != "0" || g.IssuerDeviceID != root.id || !issuerIdentityMatches(root, g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey) {
				return ErrInvalidWire
			}
		default:
			if a.PreviousGrantHash != "" {
				return ErrInvalidWire
			}
			if e := checkRight(a.ParentHash); e != nil {
				return e
			}
			if e := v.VerifyDelegatedGrant(a.Grant, a.ParentHash); e != nil {
				return e
			}
		}
		states[h] = 2
		return nil
	}
	for h := range v.authorities {
		if e = checkRight(h); e != nil {
			return nil, e
		}
	}
	for h := range v.origins {
		if e = checkOrigin(h); e != nil {
			return nil, e
		}
	}
	for _, path := range allPaths {
		for _, n := range path {
			for _, g := range n.Approval.Grants {
				if e = v.VerifyHistoricalGrant(g); e != nil {
					return nil, e
				}
			}
		}
	}
	for _, t := range p.Targets {
		a, ok := v.authorities[t.AuthorityHash]
		if !ok || a.Grant.Grant.EnvironmentID != t.EnvironmentID {
			return nil, ErrInvalidWire
		}
		v.targets[t.EnvironmentID] = t.AuthorityHash
	}
	return v, nil
}
func verifyApprovalV3(anchor ConfirmedEnrollmentAnchor, a EnrollmentApprovalV3, complete bool) (*VerifiedIssuerProofV2, error) {
	if anchor.Context != a.Context || anchor.TranscriptHash != a.TranscriptHash || issuerHistoricalContext(a.Context) != nil {
		return nil, ErrInvalidWire
	}
	c, e := a.Certificate()
	if e != nil {
		return nil, e
	}
	key, e := DecodeBase64(anchor.Context.ApproverSigningPublicKey, 32, 32)
	if e != nil {
		return nil, e
	}
	if e = VerifyEnrollmentCertificateV3(c, a.ApproverSignature, key); e != nil {
		return nil, e
	}
	if complete || a.InitiatorSignature != "" {
		ik, e := DecodeBase64(anchor.Context.InitiatorSigningPublicKey, 32, 32)
		if e != nil {
			return nil, e
		}
		if e = VerifyEnrollmentCertificateV3(c, a.InitiatorSignature, ik); e != nil {
			return nil, e
		}
	}
	p := a.IssuerProof
	r := p.TrustRoot
	v, e := VerifyIssuerEvidenceV2(PinnedIssuerRoot{p.AccountID, p.AccountGeneration, r.RootDeviceID, r.RootSigningPublicKey, r.RootReceivingPublicKey}, p, proofGenesisV2(p)...)
	if e != nil {
		return nil, e
	}
	current := issuerIdentity{r.RootDeviceID, r.RootSigningPublicKey, r.RootReceivingPublicKey}
	if len(p.Path) > 0 {
		x := p.Path[len(p.Path)-1].Approval.Context
		current = issuerIdentity{x.InitiatorDeviceID, x.InitiatorSigningPublicKey, x.InitiatorReceivingPublicKey}
	}
	if !issuerIdentityMatches(current, anchor.Context.ApproverDeviceID, anchor.Context.ApproverSigningPublicKey, anchor.Context.ApproverReceivingPublicKey) {
		return nil, ErrInvalidSignature
	}
	if _, ok := v.identities[anchor.Context.InitiatorDeviceID]; ok {
		return nil, ErrInvalidWire
	}
	for _, i := range v.identities {
		if i.signing == anchor.Context.InitiatorSigningPublicKey || i.receiving == anchor.Context.InitiatorSigningPublicKey || i.signing == anchor.Context.InitiatorReceivingPublicKey || i.receiving == anchor.Context.InitiatorReceivingPublicKey {
			return nil, ErrInvalidWire
		}
	}
	v.identities[anchor.Context.InitiatorDeviceID] = issuerIdentity{anchor.Context.InitiatorDeviceID, anchor.Context.InitiatorSigningPublicKey, anchor.Context.InitiatorReceivingPublicKey}
	if e = VerifyEnrollmentGrants(c.EnrollmentCertificate, a.Grants, key); e != nil {
		return nil, e
	}
	if len(p.Targets) != len(a.Grants) {
		return nil, ErrInvalidWire
	}
	for _, g := range a.Grants {
		h, ok := v.targets[g.Grant.EnvironmentID]
		if !ok {
			return nil, ErrInvalidWire
		}
		if e = v.VerifyDelegatedGrant(g, h); e != nil {
			return nil, e
		}
	}
	return v, nil
}
func VerifyEnrollmentApprovalV3(anchor ConfirmedEnrollmentAnchor, a EnrollmentApprovalV3, now time.Time) (*VerifiedIssuerProofV2, error) {
	e, err := strconv.ParseInt(anchor.Context.ExpiresAt, 10, 64)
	if err != nil || e <= now.Unix() || e-now.Unix() > 120 {
		return nil, ErrInvalidWire
	}
	for _, g := range a.Grants {
		if g.Grant.ExpiresAt != "0" {
			e, err := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
			if err != nil || e <= now.Unix() {
				return nil, ErrInvalidWire
			}
		}
	}
	return verifyApprovalV3(anchor, a, false)
}
func VerifyCompletedEnrollmentV3(anchor ConfirmedEnrollmentAnchor, a EnrollmentApprovalV3) (*VerifiedIssuerProofV2, error) {
	return verifyApprovalV3(anchor, a, true)
}
func VerifyHistoricalEnrollmentApprovalV3(anchor ConfirmedEnrollmentAnchor, a EnrollmentApprovalV3) (*VerifiedIssuerProofV2, error) {
	return verifyApprovalV3(anchor, a, false)
}
func SignEnrollmentApprovalV3(a EnrollmentApprovalV3, pin PinnedIssuerRoot, anchor ConfirmedEnrollmentAnchor, key ed25519.PrivateKey, now time.Time, initial ...SignedGrantWire) (EnrollmentApprovalV3, error) {
	if _, e := VerifyIssuerEvidenceV2(pin, a.IssuerProof, initial...); e != nil {
		return EnrollmentApprovalV3{}, e
	}
	if len(key) != ed25519.PrivateKeySize || EncodeBase64(key.Public().(ed25519.PublicKey)) != anchor.Context.ApproverSigningPublicKey || a.ApproverSignature != "" || a.InitiatorSignature != "" {
		return EnrollmentApprovalV3{}, ErrInvalidWire
	}
	c, e := a.Certificate()
	if e != nil {
		return EnrollmentApprovalV3{}, e
	}
	a.ApproverSignature, e = SignEnrollmentCertificateV3(c, key)
	if e != nil {
		return EnrollmentApprovalV3{}, e
	}
	if _, e = VerifyEnrollmentApprovalV3(anchor, a, now); e != nil {
		return EnrollmentApprovalV3{}, e
	}
	return a, nil
}

// VerifyEnvironmentOriginEvent 将公开控制证书与本次数据事件的原签包关联。
// 旧接收者与 actor 来源已在图中验证；不接受仅外层自称的 before 或目录公钥。
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
