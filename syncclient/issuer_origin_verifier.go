package syncclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// IssuerOriginPinnedTrust 固定受保护原始 cert3 收据；没有 Managers 或恢复锚。
type IssuerOriginPinnedTrust struct {
	AccountID              string
	AccountGeneration      uint64
	DeviceID               string
	DeviceSigningPublicKey ed25519.PublicKey
	ReceivingPrivateKey    []byte
	Receipt                EnrollmentReceiptV3
	Now                    func() time.Time
}

func NewPinnedVerifierV3(t IssuerOriginPinnedTrust) (*PinnedVerifier, error) {
	a := t.Receipt.Approval
	p, e := cryptox.VerifyCompletedEnrollmentV3(cryptox.ConfirmedEnrollmentAnchor{Context: a.Context, TranscriptHash: a.TranscriptHash}, a)
	if e != nil {
		return nil, e
	}
	v, e := newIssuerOriginPinnedVerifier(t, p)
	if e == nil {
		v.requireEvidence = true
		v.requireStoredEvidence = true
	}
	return v, e
}
func newIssuerOriginPinnedVerifier(t IssuerOriginPinnedTrust, p *cryptox.VerifiedIssuerProofV2) (*PinnedVerifier, error) {
	if p == nil || t.AccountID == "" || t.AccountGeneration == 0 || !enrollmentID.MatchString(t.DeviceID) || !enrollmentID.MatchString(t.Receipt.IdempotencyKey) || len(t.DeviceSigningPublicKey) != 32 {
		return nil, cryptox.ErrInvalidWire
	}
	sk, e := ecdh.X25519().NewPrivateKey(t.ReceivingPrivateKey)
	if e != nil {
		return nil, e
	}
	c := t.Receipt.Approval.Context
	recv := cryptox.EncodeBase64(sk.PublicKey().Bytes())
	if c.AccountID != t.AccountID || c.AccountGeneration != strconv.FormatUint(t.AccountGeneration, 10) || c.InitiatorDeviceID != t.DeviceID || c.InitiatorSigningPublicKey != cryptox.EncodeBase64(t.DeviceSigningPublicKey) || c.InitiatorReceivingPublicKey != recv || t.Receipt.Approval.CertificateVersion != "3" {
		return nil, cryptox.ErrInvalidWire
	}
	if t.Now == nil {
		t.Now = time.Now
	}
	initial := t.Receipt.Approval.IssuerProof
	// 未签本机证书只用于内部审批期 HPKE 验证，不能持久化为可信账本。
	if t.Receipt.Approval.InitiatorSignature != "" {
		initial = completedEvidenceV3(t.Receipt)
	}
	r := initial.TrustRoot
	pin := cryptox.PinnedIssuerRoot{AccountID: t.AccountID, AccountGeneration: c.AccountGeneration, DeviceID: r.RootDeviceID, SigningPublicKey: r.RootSigningPublicKey, ReceivingPublicKey: r.RootReceivingPublicKey}
	return &PinnedVerifier{trust: PinnedTrust{AccountID: t.AccountID, AccountGeneration: t.AccountGeneration, DeviceID: t.DeviceID, DeviceSigningPublicKey: bytes.Clone(t.DeviceSigningPublicKey), ReceivingPrivateKey: bytes.Clone(t.ReceivingPrivateKey), Now: t.Now}, receivingPublicKey: recv, issuerOriginProof: p, evidenceRoot: &pin, initialEvidence: &initial, genesisAuthorities: p.InitialAuthorities()}, nil
}
func completedEvidenceV3(r EnrollmentReceiptV3) cryptox.IssuerProofV2 {
	a := r.Approval
	p := a.IssuerProof
	c, _ := a.Certificate()
	node := cryptox.IssuerEnrollment{CertificateVersion: "3", IssuerProofHash: c.IssuerProofHash, Approval: cryptox.EnrollmentApproval{Context: a.Context, PairingProfile: a.PairingProfile, TranscriptHash: a.TranscriptHash, Grants: a.Grants, ApproverSignature: a.ApproverSignature, InitiatorSignature: a.InitiatorSignature}}
	p.Path = append(append([]cryptox.IssuerEnrollment(nil), p.Path...), node)
	parents := map[string]string{}
	for _, t := range p.Targets {
		parents[t.EnvironmentID] = t.AuthorityHash
	}
	p.Targets = nil
	for _, g := range a.Grants {
		h, _ := cryptox.IssuerAuthorityHash(g)
		p.Authorities = append(p.Authorities, cryptox.IssuerAuthorityV2{Grant: g, ParentHash: parents[g.Grant.EnvironmentID]})
		p.Targets = append(p.Targets, cryptox.IssuerTarget{EnvironmentID: g.Grant.EnvironmentID, AuthorityHash: h})
	}
	return p
}

// NewPinnedVerifierV2WithOrigins 是产品明确启用新能力后的历史收据升级入口。
// 旧收据与原签名不变；只从已验证原 proof/root 建立新证据账本。
func NewPinnedVerifierV2WithOrigins(t IssuerPinnedTrust) (*PinnedVerifier, error) {
	legacy, e := NewPinnedVerifierV2(t)
	if e != nil {
		return nil, e
	}
	a := t.Receipt.Approval
	old := a.IssuerProof
	p := cryptox.IssuerProofV2{Profile: cryptox.IssuerProofV2Profile, AccountID: old.AccountID, AccountGeneration: old.AccountGeneration, TrustRoot: old.TrustRoot, Path: append([]cryptox.IssuerEnrollment(nil), old.Path...), Origins: []cryptox.SignedEnvironmentOrigin{}, IdentityPaths: [][]cryptox.IssuerEnrollment{}}
	for _, n := range old.Authorities {
		p.Authorities = append(p.Authorities, cryptox.IssuerAuthorityV2{Grant: n.Grant, ParentHash: n.ParentHash})
	}
	cert, _ := a.Certificate()
	p.Path = append(p.Path, cryptox.IssuerEnrollment{CertificateVersion: "2", IssuerProofHash: cert.IssuerProofHash, Approval: cryptox.EnrollmentApproval{Context: a.Context, PairingProfile: a.PairingProfile, TranscriptHash: a.TranscriptHash, Grants: a.Grants, ApproverSignature: a.ApproverSignature, InitiatorSignature: a.InitiatorSignature}})
	parents := map[string]string{}
	for _, t := range old.Targets {
		parents[t.EnvironmentID] = t.AuthorityHash
	}
	for _, g := range a.Grants {
		h, _ := cryptox.IssuerAuthorityHash(g)
		p.Authorities = append(p.Authorities, cryptox.IssuerAuthorityV2{Grant: g, ParentHash: parents[g.Grant.EnvironmentID]})
		p.Targets = append(p.Targets, cryptox.IssuerTarget{EnvironmentID: g.Grant.EnvironmentID, AuthorityHash: h})
	}
	r := old.TrustRoot
	pin := cryptox.PinnedIssuerRoot{AccountID: old.AccountID, AccountGeneration: old.AccountGeneration, DeviceID: r.RootDeviceID, SigningPublicKey: r.RootSigningPublicKey, ReceivingPublicKey: r.RootReceivingPublicKey}
	genesis := []cryptox.SignedGrantWire{}
	for _, a := range old.Authorities {
		if a.ParentHash == "" {
			genesis = append(genesis, a.Grant)
		}
	}
	verified, e := cryptox.VerifyIssuerEvidenceV2(pin, p, genesis...)
	if e != nil {
		legacy.Close()
		return nil, e
	}
	legacy.issuerOriginProof = verified
	legacy.evidenceRoot = &pin
	legacy.initialEvidence = &p
	legacy.requireEvidence = true
	legacy.genesisAuthorities = genesis
	return legacy, nil
}

// OriginRootPinnedTrust 仅供已完成初始化并保存精确原授权的 root 手机使用。
// TrustRoot 不能由服务器目录取得，InitialAuthorities 不能由当前 self grant 猜测。
type OriginRootPinnedTrust struct {
	Trust              PinnedTrust
	Root               cryptox.TrustRoot
	InitialAuthorities []cryptox.SignedGrantWire
}

func NewRootPinnedVerifierWithOrigins(t OriginRootPinnedTrust) (*PinnedVerifier, error) {
	sk, e := ecdh.X25519().NewPrivateKey(t.Trust.ReceivingPrivateKey)
	if e != nil {
		return nil, e
	}
	r := t.Root
	if r.RootDeviceID != t.Trust.DeviceID || r.RootSigningPublicKey != cryptox.EncodeBase64(t.Trust.DeviceSigningPublicKey) || r.RootReceivingPublicKey != cryptox.EncodeBase64(sk.PublicKey().Bytes()) || len(t.InitialAuthorities) == 0 {
		return nil, cryptox.ErrInvalidWire
	}
	gen := strconv.FormatUint(t.Trust.AccountGeneration, 10)
	p := cryptox.IssuerProofV2{Profile: cryptox.IssuerProofV2Profile, AccountID: t.Trust.AccountID, AccountGeneration: gen, TrustRoot: r, Path: []cryptox.IssuerEnrollment{}, Origins: []cryptox.SignedEnvironmentOrigin{}, IdentityPaths: [][]cryptox.IssuerEnrollment{}}
	for _, g := range t.InitialAuthorities {
		h, e := cryptox.IssuerAuthorityHash(g)
		if e != nil {
			return nil, e
		}
		p.Authorities = append(p.Authorities, cryptox.IssuerAuthorityV2{Grant: g})
		p.Targets = append(p.Targets, cryptox.IssuerTarget{EnvironmentID: g.Grant.EnvironmentID, AuthorityHash: h})
	}
	pin := cryptox.PinnedIssuerRoot{AccountID: p.AccountID, AccountGeneration: gen, DeviceID: r.RootDeviceID, SigningPublicKey: r.RootSigningPublicKey, ReceivingPublicKey: r.RootReceivingPublicKey}
	proof, e := cryptox.VerifyIssuerEvidenceV2(pin, p, t.InitialAuthorities...)
	if e != nil {
		return nil, e
	}
	tr := t.Trust
	tr.Managers = map[string]ed25519.PublicKey{r.RootDeviceID: tr.DeviceSigningPublicKey}
	v, e := NewPinnedVerifier(tr)
	if e != nil {
		return nil, e
	}
	v.trust.Managers = nil
	v.issuerOriginProof = proof
	v.evidenceRoot = &pin
	v.initialEvidence = &p
	v.requireEvidence = true
	v.genesisAuthorities = append([]cryptox.SignedGrantWire(nil), t.InitialAuthorities...)
	return v, nil
}
func (c *Client) addEvidenceCapability(q url.Values) {
	if v, ok := c.config.Verifier.(*PinnedVerifier); ok && v.evidenceRoot != nil {
		if v.initialRecoveryEvidence != nil {
			q.Set("capability", cryptox.RecoveryAuthorityCapability)
		} else {
			q.Set("capability", cryptox.EnvironmentOriginCapability)
		}
	}
}
func decodeEvidence(data []byte) (cryptox.IssuerProofV2, error) {
	var p cryptox.IssuerProofV2
	if len(data) == 0 || len(data) > cryptox.MaxIssuerProofV2Bytes {
		return p, cryptox.ErrInvalidWire
	}
	if e := strictJSONBytes(data, &p); e != nil {
		return p, e
	}
	_, e := p.CanonicalBytes()
	return p, e
}
func strictJSONBytes(data []byte, out any) error {
	if e := cryptox.ValidateStrictJSON(data, cryptox.MaxIssuerProofV2Bytes); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	var x any
	if e := d.Decode(&x); e != io.EOF {
		return cryptox.ErrInvalidWire
	}
	return nil
}
func cloneEvidence(p cryptox.IssuerProofV2) cryptox.IssuerProofV2 {
	b, _ := json.Marshal(p)
	var out cryptox.IssuerProofV2
	_ = json.Unmarshal(b, &out)
	return out
}

// mergeEvidence 只联合精确相同的历史来源；任何同 ID/代际冲突随后由完整图拒绝。
func mergeEvidence(old, candidate cryptox.IssuerProofV2) (cryptox.IssuerProofV2, error) {
	out := cloneEvidence(old)
	if candidate.AccountID != old.AccountID || candidate.AccountGeneration != old.AccountGeneration || candidate.TrustRoot.RootDeviceID != old.TrustRoot.RootDeviceID || candidate.TrustRoot.RootSigningPublicKey != old.TrustRoot.RootSigningPublicKey || candidate.TrustRoot.RootReceivingPublicKey != old.TrustRoot.RootReceivingPublicKey {
		return out, cryptox.ErrInvalidSignature
	}
	// 恢复元数据可合法轮换，但不能从图中获得恢复授权；设备根精确不变。
	out.TrustRoot = candidate.TrustRoot
	out.Path = candidate.Path
	out.Targets = candidate.Targets
	rights := map[string]cryptox.IssuerAuthorityV2{}
	for _, a := range old.Authorities {
		h, _ := cryptox.IssuerAuthorityHash(a.Grant)
		rights[h] = a
	}
	for _, a := range candidate.Authorities {
		h, e := cryptox.IssuerAuthorityHash(a.Grant)
		if e != nil {
			return out, e
		}
		if prior, ok := rights[h]; ok && !sameJSON(prior, a) {
			return out, cryptox.ErrInvalidWire
		}
		rights[h] = a
	}
	out.Authorities = nil
	for _, a := range rights {
		out.Authorities = append(out.Authorities, a)
	}
	origins := map[string]cryptox.SignedEnvironmentOrigin{}
	for _, s := range append(old.Origins, candidate.Origins...) {
		h, e := cryptox.EnvironmentOriginHash(s)
		if e != nil {
			return out, e
		}
		origins[h] = s
	}
	out.Origins = nil
	for _, s := range origins {
		out.Origins = append(out.Origins, s)
	}
	paths := map[string][]cryptox.IssuerEnrollment{}
	for _, path := range append(append(old.IdentityPaths, candidate.IdentityPaths...), old.Path) {
		if len(path) == 0 {
			continue
		}
		b, _ := json.Marshal(path)
		paths[string(b)] = path
	}
	main, _ := json.Marshal(out.Path)
	delete(paths, string(main))
	out.IdentityPaths = nil
	for _, path := range paths {
		out.IdentityPaths = append(out.IdentityPaths, path)
	}
	return normalizeEvidence(out), nil
}
func (v *PinnedVerifier) withIssuerEvidence(pull Pull, previous localstate.CloudSnapshot) (*PinnedVerifier, json.RawMessage, error) {
	if v.initialRecoveryEvidence != nil {
		return v.withIssuerRecoveryEvidence(pull, previous)
	}
	if pull.IssuerRecoveryEvidence != nil {
		return nil, nil, cryptox.ErrInvalidWire
	}
	if v.evidenceRoot == nil {
		if pull.IssuerEvidence != nil || len(previous.IssuerEvidence) > 0 {
			return nil, nil, errors.New("issuer-origin capability requires a protected root pin")
		}
		return v, nil, nil
	}
	p := cloneEvidence(*v.initialEvidence)
	if len(previous.IssuerEvidence) > 0 {
		stored, e := decodeEvidence(previous.IssuerEvidence)
		if e != nil {
			return nil, nil, e
		}
		if _, e = cryptox.VerifyIssuerEvidenceV2(*v.evidenceRoot, stored, v.genesisAuthorities...); e != nil {
			return nil, nil, e
		}
		p = stored
	}
	if pull.IssuerEvidence != nil {
		candidate := *pull.IssuerEvidence
		if _, e := cryptox.VerifyIssuerEvidenceV2(*v.evidenceRoot, candidate, v.genesisAuthorities...); e != nil {
			return nil, nil, e
		}
		var e error
		p, e = mergeEvidence(p, candidate)
		if e != nil {
			return nil, nil, e
		}
	} else if v.requireEvidence {
		for _, g := range pull.Grants {
			expiry, _ := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
			if g.Grant.Role != "none" && (expiry == 0 || expiry > v.trust.Now().Unix()) {
				return nil, nil, errors.New("active readable grants require explicit issuer-origin evidence")
			}
		}
	}
	// 内部未完成入网的 HPKE 检查使用已确认 PAKE 的审批结果，未导出账本。
	if !v.requireEvidence && len(previous.IssuerEvidence) == 0 && pull.IssuerEvidence == nil {
		return v, nil, nil
	}
	proof, e := cryptox.VerifyIssuerEvidenceV2(*v.evidenceRoot, p, v.genesisAuthorities...)
	if e != nil {
		return nil, nil, e
	}
	if pull.IssuerEvidence != nil {
		for _, g := range pull.Grants {
			if g.Grant.Role == "none" {
				continue
			}
			expiry, _ := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
			if expiry != 0 && expiry <= v.trust.Now().Unix() {
				continue
			}
			if e = proof.VerifyTarget(cryptox.SignedGrantWire{Grant: g.Grant, Signature: g.Signature}, v.trust.DeviceID, cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey), v.receivingPublicKey); e != nil {
				return nil, nil, e
			}
		}
	}
	// JSON 对象字段顺序由固定 Go 类型产生，数组按 canonical 的排序归一。
	p = normalizeEvidence(p)
	encoded, e := json.Marshal(p)
	if e != nil || len(encoded) > cryptox.MaxIssuerProofV2Bytes {
		return nil, nil, cryptox.ErrInvalidWire
	}
	out := *v
	out.issuerOriginProof = proof
	return &out, encoded, nil
}
func (v *PinnedVerifier) VerifyPull(ctx context.Context, pull Pull, previous localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	if e := v.ValidateStoredIssuerEvidence(previous); e != nil {
		return localstate.CloudSnapshot{}, e
	}
	candidate, evidence, e := v.withIssuerEvidence(pull, previous)
	if e != nil {
		return localstate.CloudSnapshot{}, e
	}
	out, e := candidate.verifyPullValues(ctx, pull, previous)
	if e != nil {
		return localstate.CloudSnapshot{}, e
	}
	out.IssuerEvidence = bytes.Clone(evidence)
	if len(evidence) > 0 {
		if e = candidate.initializeCachedSources(&out, evidence); e != nil {
			return localstate.CloudSnapshot{}, e
		}
	}
	return out, nil
}
func (v *PinnedVerifier) VerifyAuthorizationRefresh(ctx context.Context, pull Pull, previous localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	if e := v.ValidateStoredIssuerEvidence(previous); e != nil {
		return localstate.CloudSnapshot{}, e
	}
	candidate, evidence, e := v.withIssuerEvidence(pull, previous)
	if e != nil {
		return localstate.CloudSnapshot{}, e
	}
	out, e := candidate.verifyAuthorizationValues(ctx, pull, previous, evidence)
	if e != nil {
		return localstate.CloudSnapshot{}, e
	}
	out.IssuerEvidence = bytes.Clone(evidence)
	if len(evidence) > 0 {
		if e = candidate.ValidateStoredIssuerEvidence(out); e != nil {
			return localstate.CloudSnapshot{}, e
		}
	}
	return out, nil
}

// ValidateStoredIssuerEvidence 在重启任何使用缓存/同步之前重新验受保护账本。
func (v *PinnedVerifier) ValidateStoredIssuerEvidence(previous localstate.CloudSnapshot) error {
	if v.initialRecoveryEvidence != nil {
		return v.validateStoredRecoveryEvidence(previous)
	}
	if previous.AccountID != "" && (previous.AccountID != v.trust.AccountID || previous.AccountGeneration != v.trust.AccountGeneration) {
		return cryptox.ErrInvalidWire
	}
	if len(previous.IssuerEvidence) == 0 {
		for _, env := range previous.Environments {
			if env.Source != nil {
				return errors.New("cached source requires a protected issuer ledger")
			}
		}
		if v.evidenceRoot == nil {
			return nil
		}
		if previous.AccountID == "" && previous.Sequence == 0 && previous.AuthorizationSequence == 0 && len(previous.Environments) == 0 {
			return nil
		}
		if v.requireStoredEvidence {
			return errors.New("cert3 cached state requires its protected issuer evidence ledger")
		}
		// 旧 cert2 / 原初始化缓存迁移只接受原受保护授权的精确版本和 fingerprint。
		targets := map[string]string{}
		rights := map[string]cryptox.SignedGrantWire{}
		for _, t := range v.initialEvidence.Targets {
			targets[t.EnvironmentID] = t.AuthorityHash
		}
		for _, a := range v.initialEvidence.Authorities {
			h, _ := cryptox.IssuerAuthorityHash(a.Grant)
			rights[h] = a.Grant
		}
		for id, env := range previous.Environments {
			s, ok := rights[targets[id]]
			g := s.Grant
			role := localstate.ReadOnly
			if g.Role == "rw" {
				role = localstate.ReadWrite
			} else if g.Role == "admin" {
				role = localstate.Admin
			}
			b, e := g.SigningBytes()
			if !ok || e != nil || g.SubjectDeviceID != v.trust.DeviceID || g.SubjectSigningPublicKey != cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey) || g.SubjectReceivingPublicKey != v.receivingPublicKey || g.KeyVersion != strconv.FormatUint(env.KeyVersion, 10) || g.GrantGeneration != strconv.FormatUint(env.GrantGeneration, 10) || env.Role != role || previous.GrantCheckpoints[id] != env.GrantGeneration || previous.GrantFingerprints[id] != digest(b) {
				return errors.New("legacy cache exceeds its exact protected enrollment evidence")
			}
			if g.ExpiresAt == "0" {
				if env.ExpiresAt != nil {
					return cryptox.ErrInvalidWire
				}
			} else if env.ExpiresAt == nil || strconv.FormatInt(env.ExpiresAt.Unix(), 10) != g.ExpiresAt {
				return cryptox.ErrInvalidWire
			}
		}
		return nil
	}
	if v.evidenceRoot == nil {
		return cryptox.ErrInvalidWire
	}
	p, e := decodeEvidence(previous.IssuerEvidence)
	if e != nil {
		return e
	}
	proof, e := cryptox.VerifyIssuerEvidenceV2(*v.evidenceRoot, p, v.genesisAuthorities...)
	if e != nil {
		return e
	}
	return v.validateIssuerCachedTargets(previous, p, proof)
}

// 有效历史图不能替代缓存当前权限绑定。授权专用投影可保留更低角色/更短
// 期限，但不能提前接受暂停期间的升级；版本、代际和签名指纹仍精确一致。
func (v *PinnedVerifier) validateIssuerCachedTargets(previous localstate.CloudSnapshot, p cryptox.IssuerProofV2, proof *cryptox.VerifiedIssuerProofV2) error {
	if previous.AccountID != v.trust.AccountID || previous.AccountGeneration != v.trust.AccountGeneration || previous.Sequence > 9007199254740991 || previous.AuthorizationSequence > 9007199254740991 {
		return cryptox.ErrInvalidWire
	}
	targets := map[string]string{}
	for _, t := range p.Targets {
		targets[t.EnvironmentID] = t.AuthorityHash
	}
	ledger, e := newCachedSourceLedger(p, proof)
	if e != nil {
		return e
	}
	projection := previous.AuthorizationSequence > previous.Sequence
	for id, env := range previous.Environments {
		if env.Source != nil {
			if env.ID != id {
				return cryptox.ErrInvalidWire
			}
			if e = v.validateSourceTarget(previous, env, ledger); e != nil {
				return e
			}
			continue
		}
		s, ok := proof.Authority(targets[id])
		g := s.Grant
		b, e := g.SigningBytes()
		if !ok || e != nil || env.ID != id || previous.DeletedEnvironments[id] != 0 || g.EnvironmentID != id || g.Role == "none" || g.KeyVersion != strconv.FormatUint(env.KeyVersion, 10) || g.GrantGeneration != strconv.FormatUint(env.GrantGeneration, 10) || previous.GrantCheckpoints[id] != env.GrantGeneration || previous.GrantFingerprints[id] != digest(b) || proof.VerifyTarget(s, v.trust.DeviceID, cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey), v.receivingPublicKey) != nil {
			return errors.New("cached environment exceeds its exact protected issuer target")
		}
		role := localstate.ReadOnly
		if g.Role == "rw" {
			role = localstate.ReadWrite
		} else if g.Role == "admin" {
			role = localstate.Admin
		}
		if issuerCacheRoleRank(env.Role) == 0 || issuerCacheRoleRank(env.Role) > issuerCacheRoleRank(role) || !projection && env.Role != role {
			return errors.New("cached role exceeds its protected issuer target")
		}
		expiry, e := strconv.ParseInt(g.ExpiresAt, 10, 64)
		if e != nil || expiry < 0 || env.ExpiresAt != nil && env.ExpiresAt.Nanosecond() != 0 {
			return cryptox.ErrInvalidWire
		}
		if expiry != 0 {
			if env.ExpiresAt == nil || env.ExpiresAt.Unix() > expiry || !projection && env.ExpiresAt.Unix() != expiry {
				return errors.New("cached expiry exceeds its protected issuer target")
			}
		} else if !projection && env.ExpiresAt != nil {
			return errors.New("cached expiry differs from its protected issuer target")
		}
	}
	return nil
}
func issuerCacheRoleRank(role localstate.Role) int {
	switch role {
	case localstate.ReadOnly:
		return 1
	case localstate.ReadWrite:
		return 2
	case localstate.Admin:
		return 3
	default:
		return 0
	}
}

func normalizeEvidence(p cryptox.IssuerProofV2) cryptox.IssuerProofV2 {
	if p.Path == nil {
		p.Path = []cryptox.IssuerEnrollment{}
	}
	if p.Authorities == nil {
		p.Authorities = []cryptox.IssuerAuthorityV2{}
	}
	if p.Targets == nil {
		p.Targets = []cryptox.IssuerTarget{}
	}
	if p.Origins == nil {
		p.Origins = []cryptox.SignedEnvironmentOrigin{}
	}
	if p.IdentityPaths == nil {
		p.IdentityPaths = [][]cryptox.IssuerEnrollment{}
	}
	sort.Slice(p.Authorities, func(i, j int) bool {
		a, b := p.Authorities[i].Grant.Grant, p.Authorities[j].Grant.Grant
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
	sort.Slice(p.Targets, func(i, j int) bool { return p.Targets[i].EnvironmentID < p.Targets[j].EnvironmentID })
	sort.Slice(p.Origins, func(i, j int) bool {
		a, _ := cryptox.EnvironmentOriginHash(p.Origins[i])
		b, _ := cryptox.EnvironmentOriginHash(p.Origins[j])
		return a < b
	})
	sort.Slice(p.IdentityPaths, func(i, j int) bool {
		a, _ := json.Marshal(p.IdentityPaths[i])
		b, _ := json.Marshal(p.IdentityPaths[j])
		return string(a) < string(b)
	})
	return p
}
