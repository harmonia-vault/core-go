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
	IssuerProofProfile    = "harmonia/issuer-proof/v1"
	IssuerProofCapability = "issuer-proof-v1"
	MaxIssuerProofPath    = 32
	MaxIssuerAuthorities  = 256
	MaxIssuerProofBytes   = 262144
)

// IssuerEnrollment 保存已完成证书的精确签名域；v1 不允许附加未签 proof hash。
type IssuerEnrollment struct {
	CertificateVersion string             `json:"certificateVersion"`
	IssuerProofHash    string             `json:"issuerProofHash"`
	Approval           EnrollmentApproval `json:"approval"`
}

// IssuerAuthority 的父摘要固定签发时采用的 Admin 证据，不产生当前管理权。
type IssuerAuthority struct {
	Grant      SignedGrantWire `json:"grant"`
	ParentHash string          `json:"parentHash"`
}
type IssuerTarget struct {
	EnvironmentID string `json:"environmentId"`
	AuthorityHash string `json:"authorityHash"`
}

// IssuerProof 只有经已确认 PAKE 的本次管理者 v2 签名认证后才可建立身份绑定。
// TrustRoot 的恢复公钥在此仅为被管理者确认的元数据，不是独立恢复授权锚。
type IssuerProof struct {
	Profile           string             `json:"profile"`
	AccountID         string             `json:"accountId"`
	AccountGeneration string             `json:"accountGeneration"`
	TrustRoot         TrustRoot          `json:"trustRoot"`
	Path              []IssuerEnrollment `json:"path"`
	Authorities       []IssuerAuthority  `json:"authorities"`
	Targets           []IssuerTarget     `json:"targets"`
}

type EnrollmentCertificateV2 struct {
	EnrollmentCertificate
	IssuerProofHash string `json:"issuerProofHash"`
}

// EnrollmentApprovalV2 是明确的新 wire 类型；旧 v1 schema 不得忽略附加字段。
type EnrollmentApprovalV2 struct {
	CertificateVersion string            `json:"certificateVersion"`
	Context            EnrollmentContext `json:"context"`
	PairingProfile     string            `json:"pairingProfile"`
	TranscriptHash     string            `json:"transcriptHash"`
	Grants             []SignedGrantWire `json:"grants"`
	IssuerProof        IssuerProof       `json:"issuerProof"`
	ApproverSignature  string            `json:"approverSignature"`
	InitiatorSignature string            `json:"initiatorSignature,omitempty"`
}

// ConfirmedEnrollmentAnchor 必须从本机真实 PAKE 确认和精确本机公钥构造。
// 此类型自身不能证明来源；调用者不得从服务器的 proof/目录复制锚。
type ConfirmedEnrollmentAnchor struct {
	Context        EnrollmentContext
	TranscriptHash string
}

func (c EnrollmentCertificateV2) SigningBytes() ([]byte, error) {
	b, err := c.EnrollmentCertificate.SigningBytes()
	if err != nil || !tokenHashPattern.MatchString(c.IssuerProofHash) {
		return nil, ErrInvalidWire
	}
	var fields []string
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, err
	}
	fields[0] = "harmonia/device-enrollment/v2"
	fields = append(fields, c.IssuerProofHash)
	return json.Marshal(fields)
}
func SignEnrollmentCertificateV2(c EnrollmentCertificateV2, key ed25519.PrivateKey) (string, error) {
	b, err := c.SigningBytes()
	if err != nil {
		return "", err
	}
	if len(key) != ed25519.PrivateKeySize {
		return "", ErrInvalidWire
	}
	public := EncodeBase64(key.Public().(ed25519.PublicKey))
	if public != c.ApproverSigningPublicKey && public != c.InitiatorSigningPublicKey {
		return "", ErrInvalidWire
	}
	return sign(key, b)
}
func VerifyEnrollmentCertificateV2(c EnrollmentCertificateV2, signature string, key ed25519.PublicKey) error {
	b, err := c.SigningBytes()
	if err != nil {
		return err
	}
	public := EncodeBase64(key)
	if public != c.ApproverSigningPublicKey && public != c.InitiatorSigningPublicKey {
		return ErrInvalidSignature
	}
	return verify(key, b, signature)
}
func (n IssuerEnrollment) CertificateBytes() ([]byte, error) {
	c, err := n.Approval.Certificate()
	if err != nil {
		return nil, err
	}
	switch n.CertificateVersion {
	case "1":
		if n.IssuerProofHash != "" {
			return nil, ErrInvalidWire
		}
		return c.SigningBytes()
	case "2":
		return (EnrollmentCertificateV2{c, n.IssuerProofHash}).SigningBytes()
	default:
		return nil, ErrInvalidWire
	}
}
func IssuerAuthorityHash(g SignedGrantWire) (string, error) {
	b, err := g.Grant.SigningBytes()
	if err != nil {
		return "", err
	}
	if _, err := DecodeBase64(g.Signature, 64, 64); err != nil {
		return "", err
	}
	return hashCanonical([]string{"harmonia/issuer-authority/v1", EncodeBase64(b), g.Signature})
}
func (p IssuerProof) CanonicalBytes() ([]byte, error) {
	if p.Profile != IssuerProofProfile || validID(p.AccountID) != nil || validDecimal(p.AccountGeneration, true) != nil || len(p.Path) > MaxIssuerProofPath || len(p.Authorities) < 1 || len(p.Authorities) > MaxIssuerAuthorities || len(p.Targets) < 1 || len(p.Targets) > MaxIssuerAuthorities {
		return nil, ErrInvalidWire
	}
	root, err := p.TrustRoot.SigningBytes(p.AccountID, p.AccountGeneration)
	if err != nil {
		return nil, err
	}
	if _, err := DecodeBase64(p.TrustRoot.Signature, 64, 64); err != nil {
		return nil, err
	}
	paths := make([][]string, 0, len(p.Path))
	for _, n := range p.Path {
		b, err := n.CertificateBytes()
		if err != nil {
			return nil, err
		}
		for _, sig := range []string{n.Approval.ApproverSignature, n.Approval.InitiatorSignature} {
			if _, err := DecodeBase64(sig, 64, 64); err != nil {
				return nil, err
			}
		}
		paths = append(paths, []string{n.CertificateVersion, EncodeBase64(b), n.Approval.ApproverSignature, n.Approval.InitiatorSignature})
	}
	authorities := append([]IssuerAuthority(nil), p.Authorities...)
	sort.Slice(authorities, func(i, j int) bool {
		a, b := authorities[i].Grant.Grant, authorities[j].Grant.Grant
		if a.EnvironmentID != b.EnvironmentID {
			return a.EnvironmentID < b.EnvironmentID
		}
		if a.SubjectDeviceID != b.SubjectDeviceID {
			return a.SubjectDeviceID < b.SubjectDeviceID
		}
		an, _ := strconv.ParseUint(a.GrantGeneration, 10, 64)
		bn, _ := strconv.ParseUint(b.GrantGeneration, 10, 64)
		return an < bn
	})
	rows := make([][]string, 0, len(authorities))
	seen := map[string]bool{}
	for _, a := range authorities {
		g := a.Grant.Grant
		b, err := g.SigningBytes()
		if err != nil {
			return nil, err
		}
		if g.Role != "admin" || (a.ParentHash != "" && !tokenHashPattern.MatchString(a.ParentHash)) {
			return nil, ErrInvalidWire
		}
		if _, err := IssuerAuthorityHash(a.Grant); err != nil {
			return nil, err
		}
		id := g.EnvironmentID + "/" + g.SubjectDeviceID + "/" + g.GrantGeneration
		if seen[id] {
			return nil, ErrInvalidWire
		}
		seen[id] = true
		rows = append(rows, []string{g.EnvironmentID, g.SubjectDeviceID, g.GrantGeneration, EncodeBase64(b), a.Grant.Signature, a.ParentHash})
	}
	targets := append([]IssuerTarget(nil), p.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].EnvironmentID < targets[j].EnvironmentID })
	targetRows := make([][]string, 0, len(targets))
	seenTargets := map[string]bool{}
	for _, t := range targets {
		if validID(t.EnvironmentID) != nil || !tokenHashPattern.MatchString(t.AuthorityHash) || seenTargets[t.EnvironmentID] {
			return nil, ErrInvalidWire
		}
		seenTargets[t.EnvironmentID] = true
		targetRows = append(targetRows, []string{t.EnvironmentID, t.AuthorityHash})
	}
	b, err := json.Marshal([]any{IssuerProofProfile, p.AccountID, p.AccountGeneration, []string{EncodeBase64(root), p.TrustRoot.Signature}, paths, rows, targetRows})
	if err != nil || len(b) > MaxIssuerProofBytes {
		return nil, ErrInvalidWire
	}
	return b, nil
}
func (p IssuerProof) Hash() (string, error) {
	b, err := p.CanonicalBytes()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func (a EnrollmentApprovalV2) Certificate() (EnrollmentCertificateV2, error) {
	if a.CertificateVersion != "2" || a.IssuerProof.AccountID != a.Context.AccountID || a.IssuerProof.AccountGeneration != a.Context.AccountGeneration {
		return EnrollmentCertificateV2{}, ErrInvalidWire
	}
	base, err := (EnrollmentApproval{a.Context, a.PairingProfile, a.TranscriptHash, a.Grants, a.ApproverSignature, a.InitiatorSignature}).Certificate()
	if err != nil {
		return EnrollmentCertificateV2{}, err
	}
	h, err := a.IssuerProof.Hash()
	if err != nil {
		return EnrollmentCertificateV2{}, err
	}
	c := EnrollmentCertificateV2{base, h}
	_, err = c.SigningBytes()
	return c, err
}

// DecodeEnrollmentApprovalV2 限制整个输入并拒绝未知字段；外层传输仍须限流。
func DecodeEnrollmentApprovalV2(data []byte) (EnrollmentApprovalV2, error) {
	if len(data) == 0 || len(data) > MaxIssuerProofBytes {
		return EnrollmentApprovalV2{}, ErrInvalidWire
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var a EnrollmentApprovalV2
	if err := decoder.Decode(&a); err != nil {
		return EnrollmentApprovalV2{}, err
	}
	var rest any
	if err := decoder.Decode(&rest); !errors.Is(err, io.EOF) {
		return EnrollmentApprovalV2{}, ErrInvalidWire
	}
	if _, err := a.Certificate(); err != nil {
		return EnrollmentApprovalV2{}, err
	}
	return a, nil
}

// IssuerBinding 只表示曾经签授的逐环境来源；没有 Active 或当前权限字段。
type IssuerBinding struct {
	EnvironmentID      string
	KeyVersion         string
	DeviceID           string
	SigningPublicKey   string
	ReceivingPublicKey string
	AuthorityHash      string
}
type issuerIdentity struct{ id, signing, receiving string }

// VerifiedIssuerProof 不暴露全局 Managers 集合，也不提供恢复公钥信任入口。
type VerifiedIssuerProof struct {
	accountID         string
	accountGeneration string
	identities        map[string]issuerIdentity
	authorities       map[string]IssuerAuthority
}

func issuerExpiryWithin(child, parent string) bool {
	c, e := strconv.ParseUint(child, 10, 64)
	if e != nil || c > 253402300799 {
		return false
	}
	p, e := strconv.ParseUint(parent, 10, 64)
	if e != nil || p > 253402300799 {
		return false
	}
	return p == 0 || (c != 0 && c <= p)
}
func issuerIdentityMatches(i issuerIdentity, id, signing, receiving string) bool {
	return i.id == id && i.signing == signing && i.receiving == receiving
}
func issuerHistoricalContext(c EnrollmentContext) error {
	expires, err := strconv.ParseUint(c.ExpiresAt, 10, 64)
	if c.Purpose != "enroll-device" || err != nil || expires > 253402300799 {
		return ErrInvalidWire
	}
	return nil
}
func (v *VerifiedIssuerProof) IssuerBindings() []IssuerBinding {
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

// VerifyDelegatedGrant 验证精确历史 Admin 来源与签名字节，不判断其当前未撤销。
// 当前使用还必须核对服务器逐次权限、本地已见代际/检查点及到期状态。
func (v *VerifiedIssuerProof) VerifyDelegatedGrant(s SignedGrantWire, authorityHash string) error {
	a, ok := v.authorities[authorityHash]
	if !ok {
		return ErrInvalidSignature
	}
	parent, g := a.Grant.Grant, s.Grant
	if g.AccountID != v.accountID || g.AccountGeneration != v.accountGeneration || parent.EnvironmentID != g.EnvironmentID || parent.KeyVersion != g.KeyVersion || parent.SubjectDeviceID != g.IssuerDeviceID {
		return ErrInvalidSignature
	}
	if validatePublicPair(g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey) != nil {
		return ErrInvalidWire
	}
	if g.Role != "none" && !issuerExpiryWithin(g.ExpiresAt, parent.ExpiresAt) {
		return ErrInvalidWire
	}
	key, _ := DecodeBase64(parent.SubjectSigningPublicKey, 32, 32)
	return VerifyGrant(s.SignedGrant(), ed25519.PublicKey(key))
}

// VerifyHistoricalGrant 只能用于签名来源检查，不可把成功结果作为当前管理权。
func (v *VerifiedIssuerProof) VerifyHistoricalGrant(s SignedGrantWire) error {
	for h := range v.authorities {
		if v.VerifyDelegatedGrant(s, h) == nil {
			return nil
		}
	}
	return ErrInvalidSignature
}

// VerifyEnrollmentApprovalV2 的锚必须来自本机已经双向确认的 PAKE Session。
// 完成前只验证审批者签名；最终可信入网还需新设备签名和服务器原子完成。
func VerifyEnrollmentApprovalV2(anchor ConfirmedEnrollmentAnchor, a EnrollmentApprovalV2, now time.Time) (*VerifiedIssuerProof, error) {
	expires, err := strconv.ParseInt(anchor.Context.ExpiresAt, 10, 64)
	if err != nil || expires <= now.Unix() || expires-now.Unix() > 120 {
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
	return verifyEnrollmentIssuerProof(anchor, a, false)
}

// VerifyCompletedEnrollmentV2 用于受保护的历史双签收据；过期挑战仍可验签，
// 但它不能恢复已经撤销/过期的当前权限。缺新设备签名时拒绝。
func VerifyCompletedEnrollmentV2(anchor ConfirmedEnrollmentAnchor, a EnrollmentApprovalV2) (*VerifiedIssuerProof, error) {
	return verifyEnrollmentIssuerProof(anchor, a, true)
}

func verifyEnrollmentIssuerProof(anchor ConfirmedEnrollmentAnchor, a EnrollmentApprovalV2, complete bool) (*VerifiedIssuerProof, error) {
	if anchor.Context != a.Context || anchor.TranscriptHash != a.TranscriptHash || issuerHistoricalContext(a.Context) != nil {
		return nil, ErrInvalidWire
	}
	cert, err := a.Certificate()
	if err != nil {
		return nil, err
	}
	approverKey, err := DecodeBase64(anchor.Context.ApproverSigningPublicKey, 32, 32)
	if err != nil {
		return nil, err
	}
	// 先验证本机 PAKE 锚的签名，再处理服务器提供的所谓 root/目录。
	if err := VerifyEnrollmentCertificateV2(cert, a.ApproverSignature, approverKey); err != nil {
		return nil, err
	}
	if complete || a.InitiatorSignature != "" {
		initiatorKey, err := DecodeBase64(anchor.Context.InitiatorSigningPublicKey, 32, 32)
		if err != nil {
			return nil, err
		}
		if err := VerifyEnrollmentCertificateV2(cert, a.InitiatorSignature, initiatorKey); err != nil {
			return nil, err
		}
	}
	p := a.IssuerProof
	// 同一 subject generation 或幂等标识不能在路径/证据/本次授权中分叉。
	seenGenerations, seenOperations := map[string]string{}, map[string]string{}
	checkGrant := func(s SignedGrantWire) error {
		g := s.Grant
		h, err := IssuerAuthorityHash(s)
		if err != nil {
			return err
		}
		if g.AccountID != p.AccountID || g.AccountGeneration != p.AccountGeneration {
			return ErrInvalidWire
		}
		for id, table := range map[string]map[string]string{
			"generation/" + g.EnvironmentID + "/" + g.SubjectDeviceID + "/" + g.GrantGeneration: seenGenerations,
			"operation/" + g.IssuerDeviceID + "/" + g.IdempotencyKey:                            seenOperations,
		} {
			if old, exists := table[id]; exists && old != h {
				return ErrInvalidWire
			}
			table[id] = h
		}
		return nil
	}
	for _, n := range p.Path {
		for _, s := range n.Approval.Grants {
			if err := checkGrant(s); err != nil {
				return nil, err
			}
		}
	}
	for _, source := range p.Authorities {
		if err := checkGrant(source.Grant); err != nil {
			return nil, err
		}
	}
	for _, s := range a.Grants {
		if err := checkGrant(s); err != nil {
			return nil, err
		}
	}
	root := issuerIdentity{p.TrustRoot.RootDeviceID, p.TrustRoot.RootSigningPublicKey, p.TrustRoot.RootReceivingPublicKey}
	// 这里只检查声明自洽；此恢复公钥不会成为 VerifiedIssuerProof 的授权锚。
	recoveryKey, err := DecodeBase64(p.TrustRoot.RecoverySigningPublicKey, 32, 32)
	if err != nil {
		return nil, err
	}
	if err := VerifyTrustRoot(p.AccountID, p.AccountGeneration, p.TrustRoot, recoveryKey); err != nil {
		return nil, err
	}
	identities := map[string]issuerIdentity{}
	usedKeys := map[string]bool{p.TrustRoot.RecoverySigningPublicKey: true, p.TrustRoot.RecoveryReceivingPublicKey: true}
	addIdentity := func(i issuerIdentity) error {
		if validID(i.id) != nil || validatePublicPair(i.signing, i.receiving) != nil || identities[i.id].id != "" || usedKeys[i.signing] || usedKeys[i.receiving] {
			return ErrInvalidWire
		}
		identities[i.id] = i
		usedKeys[i.signing] = true
		usedKeys[i.receiving] = true
		return nil
	}
	if err := addIdentity(root); err != nil {
		return nil, err
	}
	current := root
	for _, n := range p.Path {
		old := n.Approval.Context
		if old.AccountID != p.AccountID || old.AccountGeneration != p.AccountGeneration || issuerHistoricalContext(old) != nil || !issuerIdentityMatches(current, old.ApproverDeviceID, old.ApproverSigningPublicKey, old.ApproverReceivingPublicKey) {
			return nil, ErrInvalidWire
		}
		b, err := n.CertificateBytes()
		if err != nil {
			return nil, err
		}
		parentKey, _ := DecodeBase64(current.signing, 32, 32)
		if err := verify(parentKey, b, n.Approval.ApproverSignature); err != nil {
			return nil, err
		}
		child := issuerIdentity{old.InitiatorDeviceID, old.InitiatorSigningPublicKey, old.InitiatorReceivingPublicKey}
		if err := addIdentity(child); err != nil {
			return nil, err
		}
		childKey, _ := DecodeBase64(child.signing, 32, 32)
		if err := verify(childKey, b, n.Approval.InitiatorSignature); err != nil {
			return nil, err
		}
		base, err := n.Approval.Certificate()
		if err != nil {
			return nil, err
		}
		if err := VerifyEnrollmentGrants(base, n.Approval.Grants, parentKey); err != nil {
			return nil, err
		}
		current = child
	}
	if !issuerIdentityMatches(current, anchor.Context.ApproverDeviceID, anchor.Context.ApproverSigningPublicKey, anchor.Context.ApproverReceivingPublicKey) {
		return nil, ErrInvalidSignature
	}
	if identities[anchor.Context.InitiatorDeviceID].id != "" || usedKeys[anchor.Context.InitiatorSigningPublicKey] || usedKeys[anchor.Context.InitiatorReceivingPublicKey] {
		return nil, ErrInvalidWire
	}
	v := &VerifiedIssuerProof{p.AccountID, p.AccountGeneration, identities, map[string]IssuerAuthority{}}
	for _, a := range p.Authorities {
		g := a.Grant.Grant
		subject, ok := identities[g.SubjectDeviceID]
		issuer, issuerOK := identities[g.IssuerDeviceID]
		if !ok || !issuerOK || g.Role != "admin" || g.AccountID != p.AccountID || g.AccountGeneration != p.AccountGeneration || !issuerIdentityMatches(subject, g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey) {
			return nil, ErrInvalidWire
		}
		issuerKey, _ := DecodeBase64(issuer.signing, 32, 32)
		if err := VerifyGrant(a.Grant.SignedGrant(), issuerKey); err != nil {
			return nil, err
		}
		if !issuerExpiryWithin(g.ExpiresAt, "0") {
			return nil, ErrInvalidWire
		}
		h, err := IssuerAuthorityHash(a.Grant)
		if err != nil {
			return nil, err
		}
		if _, exists := v.authorities[h]; exists {
			return nil, ErrInvalidWire
		}
		v.authorities[h] = a
	}
	states := map[string]uint8{}
	var checkAuthority func(string) error
	checkAuthority = func(h string) error {
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
		if a.ParentHash == "" {
			if g.IssuerDeviceID != root.id || !issuerIdentityMatches(root, g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey) {
				return ErrInvalidWire
			}
		} else {
			if err := checkAuthority(a.ParentHash); err != nil {
				return err
			}
			if err := v.VerifyDelegatedGrant(a.Grant, a.ParentHash); err != nil {
				return err
			}
		}
		states[h] = 2
		return nil
	}
	for h := range v.authorities {
		if err := checkAuthority(h); err != nil {
			return nil, err
		}
	}
	for _, n := range p.Path {
		for _, g := range n.Approval.Grants {
			if err := v.VerifyHistoricalGrant(g); err != nil {
				return nil, err
			}
		}
	}
	if err := VerifyEnrollmentGrants(cert.EnrollmentCertificate, a.Grants, approverKey); err != nil {
		return nil, err
	}
	if len(p.Targets) != len(a.Grants) {
		return nil, ErrInvalidWire
	}
	targets := map[string]string{}
	for _, t := range p.Targets {
		targets[t.EnvironmentID] = t.AuthorityHash
	}
	for _, g := range a.Grants {
		h, ok := targets[g.Grant.EnvironmentID]
		if !ok {
			return nil, ErrInvalidWire
		}
		if err := v.VerifyDelegatedGrant(g, h); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// PinnedIssuerRoot 必须来自管理手机既有受保护收据或已完成初始化，不来自服务器。
// 这里仅固定根设备身份；恢复钥的可信来源仍属于独立恢复流程。
type PinnedIssuerRoot struct {
	AccountID          string
	AccountGeneration  string
	DeviceID           string
	SigningPublicKey   string
	ReceivingPublicKey string
}

// SignEnrollmentApprovalV2 是批准工作流的预签入口。管理手机先把待签 proof
// 与既有根 pin、真实 PAKE 双向确认及精确本机钥绑定，完整验证后才返回签名。
func SignEnrollmentApprovalV2(a EnrollmentApprovalV2, root PinnedIssuerRoot, anchor ConfirmedEnrollmentAnchor, key ed25519.PrivateKey, now time.Time) (EnrollmentApprovalV2, error) {
	if root.AccountID != a.Context.AccountID || root.AccountGeneration != a.Context.AccountGeneration || root.DeviceID != a.IssuerProof.TrustRoot.RootDeviceID || root.SigningPublicKey != a.IssuerProof.TrustRoot.RootSigningPublicKey || root.ReceivingPublicKey != a.IssuerProof.TrustRoot.RootReceivingPublicKey {
		return EnrollmentApprovalV2{}, ErrInvalidSignature
	}
	if len(key) != ed25519.PrivateKeySize || EncodeBase64(key.Public().(ed25519.PublicKey)) != anchor.Context.ApproverSigningPublicKey || a.ApproverSignature != "" || a.InitiatorSignature != "" {
		return EnrollmentApprovalV2{}, ErrInvalidWire
	}
	c, err := a.Certificate()
	if err != nil {
		return EnrollmentApprovalV2{}, err
	}
	signature, err := SignEnrollmentCertificateV2(c, key)
	if err != nil {
		return EnrollmentApprovalV2{}, err
	}
	a.ApproverSignature = signature
	if _, err := VerifyEnrollmentApprovalV2(anchor, a, now); err != nil {
		return EnrollmentApprovalV2{}, err
	}
	return a, nil
}
