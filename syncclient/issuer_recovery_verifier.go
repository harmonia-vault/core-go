package syncclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// verifiedAuthorityGraph 只接受成熟原语完整验证产生的对象，不接收裸目录。
type verifiedAuthorityGraph interface {
	VerifyHistoricalGrant(cryptox.SignedGrantWire) error
	VerifyTarget(cryptox.SignedGrantWire, string, string, string) error
	IssuerBindings() []cryptox.IssuerBinding
	Authority(string) (cryptox.SignedGrantWire, bool)
	VerifyEnvironmentOriginEvent(cryptox.SignedEnvironmentChange, cryptox.SignedEnvironmentOrigin, cryptox.SignedGrantWire) error
}

type IssuerRecoveryPinnedTrust struct {
	AccountID              string
	AccountGeneration      uint64
	DeviceID               string
	DeviceSigningPublicKey ed25519.PublicKey
	ReceivingPrivateKey    []byte
	Receipt                EnrollmentReceiptV4
	Now                    func() time.Time
}

// RecoveredDevicePinnedTrust 的 Pin/Accepted 来自本机已验证并受保护保存的
// 原初始化与恢复流程；HTTP 目录或当前 self grant 不能代替这些材料。
type RecoveredDevicePinnedTrust struct {
	Trust    PinnedTrust
	Pin      cryptox.PinnedIssuerRoot
	Evidence cryptox.IssuerRecoveryProof
	Accepted cryptox.AcceptedRecoveredDevice
}

func NewPinnedVerifierV4(t IssuerRecoveryPinnedTrust) (*PinnedVerifier, error) {
	a := t.Receipt.Approval
	p, e := cryptox.VerifyCompletedEnrollmentV4(cryptox.ConfirmedEnrollmentAnchor{Context: a.Context, TranscriptHash: a.TranscriptHash}, a)
	if e != nil {
		return nil, e
	}
	v, e := newIssuerRecoveryPinnedVerifier(t, p)
	if e == nil {
		v.requireEvidence = true
		v.requireStoredEvidence = true
	}
	return v, e
}
func newIssuerRecoveryPinnedVerifier(t IssuerRecoveryPinnedTrust, p *cryptox.VerifiedIssuerRecoveryProof) (*PinnedVerifier, error) {
	if p == nil || t.AccountID == "" || t.AccountGeneration == 0 || !enrollmentID.MatchString(t.DeviceID) || !enrollmentID.MatchString(t.Receipt.IdempotencyKey) || len(t.DeviceSigningPublicKey) != 32 {
		return nil, cryptox.ErrInvalidWire
	}
	sk, e := ecdh.X25519().NewPrivateKey(t.ReceivingPrivateKey)
	if e != nil {
		return nil, e
	}
	a := t.Receipt.Approval
	c := a.Context
	recv := cryptox.EncodeBase64(sk.PublicKey().Bytes())
	if c.AccountID != t.AccountID || c.AccountGeneration != strconv.FormatUint(t.AccountGeneration, 10) || c.InitiatorDeviceID != t.DeviceID || c.InitiatorSigningPublicKey != cryptox.EncodeBase64(t.DeviceSigningPublicKey) || c.InitiatorReceivingPublicKey != recv || a.CertificateVersion != "4" {
		return nil, cryptox.ErrInvalidWire
	}
	if t.Now == nil {
		t.Now = time.Now
	}
	initial := cloneRecoveryEvidence(a.IssuerProof)
	if a.InitiatorSignature != "" {
		initial = completedEvidenceV4(t.Receipt)
	}
	root := initial.Initialization.Proposal.Device
	pin := cryptox.PinnedIssuerRoot{AccountID: t.AccountID, AccountGeneration: c.AccountGeneration, DeviceID: root.ID, SigningPublicKey: root.SigningPublicKey, ReceivingPublicKey: root.ReceivingPublicKey}
	// 原根双签由已确认 PAKE 的原 receipt 认证；随后的候选永远使用这一本机固定 pin。
	return &PinnedVerifier{trust: PinnedTrust{AccountID: t.AccountID, AccountGeneration: t.AccountGeneration, DeviceID: t.DeviceID, DeviceSigningPublicKey: bytes.Clone(t.DeviceSigningPublicKey), ReceivingPrivateKey: bytes.Clone(t.ReceivingPrivateKey), Now: t.Now}, receivingPublicKey: recv, issuerOriginProof: p, evidenceRoot: &pin, initialRecoveryEvidence: &initial, genesisAuthorities: p.InitialAuthorities()}, nil
}
func completedEvidenceV4(r EnrollmentReceiptV4) cryptox.IssuerRecoveryProof {
	a := r.Approval
	p := cloneRecoveryEvidence(a.IssuerProof)
	cert, _ := a.Certificate()
	node := cryptox.IssuerEnrollment{CertificateVersion: "4", IssuerProofHash: cert.IssuerProofHash, Approval: cryptox.EnrollmentApproval{Context: a.Context, PairingProfile: a.PairingProfile, TranscriptHash: a.TranscriptHash, Grants: a.Grants, ApproverSignature: a.ApproverSignature, InitiatorSignature: a.InitiatorSignature}}
	p.Path = append(p.Path, cryptox.IssuerRecoveryArchive{Kind: "paired", Enrollment: &node})
	parents := map[string]string{}
	for _, t := range p.Targets {
		parents[t.EnvironmentID] = t.AuthorityHash
	}
	p.Targets = []cryptox.IssuerTarget{}
	for _, g := range a.Grants {
		h, _ := cryptox.IssuerAuthorityHash(g)
		p.Authorities = append(p.Authorities, cryptox.IssuerRecoveryAuthority{Grant: g, ParentHash: parents[g.Grant.EnvironmentID]})
		p.Targets = append(p.Targets, cryptox.IssuerTarget{EnvironmentID: g.Grant.EnvironmentID, AuthorityHash: h})
	}
	return p
}
func NewRecoveredDevicePinnedVerifier(t RecoveredDevicePinnedTrust) (*PinnedVerifier, error) {
	tr := t.Trust
	if len(tr.Managers) != 0 || tr.AccountID == "" || tr.AccountGeneration == 0 || !enrollmentID.MatchString(tr.DeviceID) || len(tr.DeviceSigningPublicKey) != 32 || t.Pin.AccountID != tr.AccountID || t.Pin.AccountGeneration != strconv.FormatUint(tr.AccountGeneration, 10) {
		return nil, cryptox.ErrInvalidWire
	}
	sk, e := ecdh.X25519().NewPrivateKey(tr.ReceivingPrivateKey)
	if e != nil {
		return nil, e
	}
	recv := cryptox.EncodeBase64(sk.PublicKey().Bytes())
	p := cloneRecoveryEvidence(t.Evidence)
	proof, e := cryptox.VerifyIssuerRecoveryEvidence(t.Pin, p)
	if e != nil {
		return nil, e
	}
	accepted := t.Accepted
	own := accepted.Submission.Enrollment
	if accepted.Sequence == 0 || own.AccountID != tr.AccountID || own.AccountGeneration != t.Pin.AccountGeneration || own.DeviceID != tr.DeviceID || own.DeviceSigningPublicKey != cryptox.EncodeBase64(tr.DeviceSigningPublicKey) || own.DeviceReceivingPublicKey != recv {
		return nil, cryptox.ErrInvalidWire
	}
	h, e := cryptox.RecoveredDeviceReferenceHash(accepted.Submission)
	if e != nil {
		return nil, e
	}
	found := false
	for _, r := range p.RecoveredDevices {
		hash, e := cryptox.RecoveredDeviceReferenceHash(r.Submission)
		if e != nil {
			return nil, e
		}
		if hash == h {
			if !sameJSON(r, accepted) {
				return nil, cryptox.ErrInvalidWire
			}
			found = true
		}
	}
	if !found || len(p.Path) != 1 || p.Path[0].Kind != "recovered" || p.Path[0].RecoveryEnrollmentHash != h || len(p.Targets) != len(accepted.Submission.Grants) {
		return nil, cryptox.ErrInvalidWire
	}
	for _, g := range accepted.Submission.Grants {
		if e = proof.VerifyTarget(g, tr.DeviceID, own.DeviceSigningPublicKey, recv); e != nil {
			return nil, e
		}
	}
	if tr.Now == nil {
		tr.Now = time.Now
	}
	tr.DeviceSigningPublicKey = bytes.Clone(tr.DeviceSigningPublicKey)
	tr.ReceivingPrivateKey = bytes.Clone(tr.ReceivingPrivateKey)
	pin := t.Pin
	return &PinnedVerifier{trust: tr, receivingPublicKey: recv, issuerOriginProof: proof, evidenceRoot: &pin, initialRecoveryEvidence: &p, genesisAuthorities: proof.InitialAuthorities(), requireEvidence: true, requireStoredEvidence: true}, nil
}

// 服务端同名 issuerEvidence 字段只按明确能力解码；旧 parser 不接新 profile。
func (c *Client) requestPull(ctx context.Context, u *url.URL, out *Pull) error {
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.initialRecoveryEvidence == nil {
		return c.request(ctx, http.MethodGet, u, nil, out)
	}
	var wire struct {
		IssuerEvidence    *cryptox.IssuerRecoveryProof `json:"issuerEvidence,omitempty"`
		Scope             string                       `json:"scope,omitempty"`
		EnvironmentEvents []EnvironmentEvent           `json:"environmentEvents,omitempty"`
		AccountID         string                       `json:"accountId"`
		AccountGeneration string                       `json:"accountGeneration"`
		Sequence          uint64                       `json:"sequence"`
		Grants            []SignedGrant                `json:"grants"`
		Events            []Event                      `json:"events"`
	}
	if e := c.request(ctx, http.MethodGet, u, nil, &wire); e != nil {
		return e
	}
	*out = Pull{IssuerRecoveryEvidence: wire.IssuerEvidence, Scope: wire.Scope, EnvironmentEvents: wire.EnvironmentEvents, AccountID: wire.AccountID, AccountGeneration: wire.AccountGeneration, Sequence: wire.Sequence, Grants: wire.Grants, Events: wire.Events}
	return nil
}
func cloneRecoveryEvidence(p cryptox.IssuerRecoveryProof) cryptox.IssuerRecoveryProof {
	b, _ := json.Marshal(p)
	var out cryptox.IssuerRecoveryProof
	_ = json.Unmarshal(b, &out)
	return out
}
func decodeRecoveryEvidence(data []byte) (cryptox.IssuerRecoveryProof, error) {
	return cryptox.DecodeIssuerRecoveryProof(data)
}

// 合并仅保存已验历史；恢复链使用候选的完整连续链，并要求保留原已见链尾。
func mergeRecoveryEvidence(old, candidate cryptox.IssuerRecoveryProof) (cryptox.IssuerRecoveryProof, error) {
	if old.AccountID != candidate.AccountID || old.AccountGeneration != candidate.AccountGeneration || !sameJSON(old.Initialization, candidate.Initialization) {
		return cryptox.IssuerRecoveryProof{}, cryptox.ErrInvalidWire
	}
	out := cloneRecoveryEvidence(old)
	out.TrustRoot = candidate.TrustRoot
	out.Transitions = candidate.Transitions
	nodes := map[string]cryptox.IssuerRecoveryAuthority{}
	for _, n := range append(out.Authorities, candidate.Authorities...) {
		h, e := cryptox.IssuerAuthorityHash(n.Grant)
		if e != nil {
			return out, e
		}
		if seen, ok := nodes[h]; ok && !sameJSON(seen, n) {
			return out, cryptox.ErrInvalidWire
		}
		nodes[h] = n
	}
	out.Authorities = []cryptox.IssuerRecoveryAuthority{}
	for _, n := range nodes {
		out.Authorities = append(out.Authorities, n)
	}
	origins := map[string]cryptox.SignedEnvironmentOrigin{}
	for _, n := range append(out.Origins, candidate.Origins...) {
		h, e := cryptox.EnvironmentOriginHash(n)
		if e != nil {
			return out, e
		}
		if seen, ok := origins[h]; ok && !sameJSON(seen, n) {
			return out, cryptox.ErrInvalidWire
		}
		origins[h] = n
	}
	out.Origins = []cryptox.SignedEnvironmentOrigin{}
	for _, n := range origins {
		out.Origins = append(out.Origins, n)
	}
	recovered := map[string]cryptox.AcceptedRecoveredDevice{}
	for _, n := range append(out.RecoveredDevices, candidate.RecoveredDevices...) {
		h, e := cryptox.RecoveredDeviceReferenceHash(n.Submission)
		if e != nil {
			return out, e
		}
		if seen, ok := recovered[h]; ok && !sameJSON(seen, n) {
			return out, cryptox.ErrInvalidWire
		}
		recovered[h] = n
	}
	out.RecoveredDevices = []cryptox.AcceptedRecoveredDevice{}
	for _, n := range recovered {
		out.RecoveredDevices = append(out.RecoveredDevices, n)
	}
	paths := map[string][]cryptox.IssuerRecoveryArchive{}
	all := append(append([][]cryptox.IssuerRecoveryArchive{out.Path, candidate.Path}, out.IdentityPaths...), candidate.IdentityPaths...)
	for _, path := range all {
		if len(path) > 0 {
			b, _ := json.Marshal(path)
			paths[string(b)] = path
		}
	}
	out.Path = candidate.Path
	main, _ := json.Marshal(out.Path)
	delete(paths, string(main))
	out.IdentityPaths = [][]cryptox.IssuerRecoveryArchive{}
	for _, path := range paths {
		out.IdentityPaths = append(out.IdentityPaths, path)
	}
	targets := map[string]cryptox.IssuerTarget{}
	for _, t := range append(out.Targets, candidate.Targets...) {
		targets[t.EnvironmentID] = t
	}
	out.Targets = []cryptox.IssuerTarget{}
	for _, t := range targets {
		out.Targets = append(out.Targets, t)
	}
	normalizeRecoveryEvidence(&out)
	return out, nil
}
func normalizeRecoveryEvidence(p *cryptox.IssuerRecoveryProof) {
	sort.Slice(p.Authorities, func(i, j int) bool {
		a, _ := cryptox.IssuerAuthorityHash(p.Authorities[i].Grant)
		b, _ := cryptox.IssuerAuthorityHash(p.Authorities[j].Grant)
		return a < b
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
	sort.Slice(p.RecoveredDevices, func(i, j int) bool { return p.RecoveredDevices[i].Sequence < p.RecoveredDevices[j].Sequence })
}
func (v *PinnedVerifier) withIssuerRecoveryEvidence(pull Pull, previous localstate.CloudSnapshot) (*PinnedVerifier, json.RawMessage, error) {
	if pull.IssuerEvidence != nil || v.evidenceRoot == nil {
		return nil, nil, cryptox.ErrInvalidWire
	}
	p := cloneRecoveryEvidence(*v.initialRecoveryEvidence)
	prior, e := cryptox.VerifyIssuerRecoveryEvidence(*v.evidenceRoot, p)
	if e != nil {
		return nil, nil, e
	}
	if len(previous.IssuerEvidence) > 0 {
		stored, e := decodeRecoveryEvidence(previous.IssuerEvidence)
		if e != nil {
			return nil, nil, e
		}
		prior, e = cryptox.VerifyRecoveryCheckpointAdvance(prior, stored)
		if e != nil {
			return nil, nil, e
		}
		p = stored
	}
	if pull.IssuerRecoveryEvidence != nil {
		candidate := *pull.IssuerRecoveryEvidence
		if _, e = cryptox.VerifyRecoveryCheckpointAdvance(prior, candidate); e != nil {
			return nil, nil, e
		}
		p, e = mergeRecoveryEvidence(p, candidate)
		if e != nil {
			return nil, nil, e
		}
	} else if v.requireEvidence {
		for _, g := range pull.Grants {
			expiry, _ := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
			if g.Grant.Role != "none" && (expiry == 0 || expiry > v.trust.Now().Unix()) {
				return nil, nil, errors.New("active grants require explicit issuer-recovery evidence")
			}
		}
	}
	if !v.requireEvidence && len(previous.IssuerEvidence) == 0 && pull.IssuerRecoveryEvidence == nil {
		return v, nil, nil
	}
	proof, e := cryptox.VerifyRecoveryCheckpointAdvance(prior, p)
	if e != nil {
		return nil, nil, e
	}
	if pull.IssuerRecoveryEvidence != nil {
		for _, g := range pull.Grants {
			expiry, _ := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
			if g.Grant.Role != "none" && (expiry == 0 || expiry > v.trust.Now().Unix()) {
				if e = proof.VerifyTarget(cryptox.SignedGrantWire{Grant: g.Grant, Signature: g.Signature}, v.trust.DeviceID, cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey), v.receivingPublicKey); e != nil {
					return nil, nil, e
				}
			}
		}
	}
	if v.requireEvidence || len(previous.IssuerEvidence) > 0 {
		if e = validateRecoveryLedgerSequence(p, pull.Sequence); e != nil {
			return nil, nil, e
		}
	}
	encoded, e := json.Marshal(p)
	if e != nil || len(encoded) > cryptox.MaxRecoveryAuthorityBytes {
		return nil, nil, cryptox.ErrInvalidWire
	}
	out := *v
	out.issuerOriginProof = proof
	return &out, encoded, nil
}
func (v *PinnedVerifier) cachedLedger(data []byte) (*cachedSourceLedger, error) {
	if v.initialRecoveryEvidence == nil {
		p, e := decodeEvidence(data)
		if e != nil {
			return nil, e
		}
		return newCachedSourceLedger(p, v.issuerOriginProof)
	}
	p, e := decodeRecoveryEvidence(data)
	if e != nil {
		return nil, e
	}
	// 这里仅转投路径元数据；签名/恢复链早已由 proof3 对象完整核验，不调用 v2 验证降级。
	l := &cachedSourceLedger{proof: v.issuerOriginProof, rights: map[string]cryptox.IssuerAuthorityV2{}, origins: map[string]cryptox.SignedEnvironmentOrigin{}, targets: map[string]string{}}
	for _, n := range p.Authorities {
		h, e := cryptox.IssuerAuthorityHash(n.Grant)
		if e != nil {
			return nil, e
		}
		l.rights[h] = cryptox.IssuerAuthorityV2{Grant: n.Grant, ParentHash: n.ParentHash, OriginHash: n.OriginHash, PreviousGrantHash: n.PreviousGrantHash}
	}
	for _, o := range p.Origins {
		h, e := cryptox.EnvironmentOriginHash(o)
		if e != nil {
			return nil, e
		}
		l.origins[h] = o
	}
	for _, t := range p.Targets {
		l.targets[t.EnvironmentID] = t.AuthorityHash
	}
	return l, nil
}
func (v *PinnedVerifier) validateStoredRecoveryEvidence(previous localstate.CloudSnapshot) error {
	if previous.AccountID != "" && (previous.AccountID != v.trust.AccountID || previous.AccountGeneration != v.trust.AccountGeneration) {
		return cryptox.ErrInvalidWire
	}
	if len(previous.IssuerEvidence) == 0 {
		if previous.AccountID == "" && previous.Sequence == 0 && previous.AuthorizationSequence == 0 && len(previous.Environments) == 0 {
			return nil
		}
		return errors.New("cert4 cached state requires protected issuer-recovery ledger")
	}
	p, e := decodeRecoveryEvidence(previous.IssuerEvidence)
	if e != nil {
		return e
	}
	initial, e := cryptox.VerifyIssuerRecoveryEvidence(*v.evidenceRoot, *v.initialRecoveryEvidence)
	if e != nil {
		return e
	}
	proof, e := cryptox.VerifyRecoveryCheckpointAdvance(initial, p)
	if e != nil {
		return e
	}
	if previous.AccountID != v.trust.AccountID || previous.AccountGeneration != v.trust.AccountGeneration || previous.Sequence > 9007199254740991 || previous.AuthorizationSequence > 9007199254740991 {
		return cryptox.ErrInvalidWire
	}
	checkpoint := previous.Sequence
	if checkpoint < previous.AuthorizationSequence {
		checkpoint = previous.AuthorizationSequence
	}
	if e = validateRecoveryLedgerSequence(p, checkpoint); e != nil {
		return e
	}
	clone := *v
	clone.issuerOriginProof = proof
	l, e := clone.cachedLedger(previous.IssuerEvidence)
	if e != nil {
		return e
	}
	for id, env := range previous.Environments {
		if env.ID != id || env.Source == nil {
			return cryptox.ErrInvalidWire
		}
		if e = clone.validateSourceTarget(previous, env, l); e != nil {
			return e
		}
	}
	return nil
}

// CurrentIssuerRecoveryEvidence 返回受保护账本的深拷贝；不会公开 bearer 或私钥。
func (c *Client) CurrentIssuerRecoveryEvidence() (cryptox.IssuerRecoveryProof, error) {
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.initialRecoveryEvidence == nil {
		return cryptox.IssuerRecoveryProof{}, cryptox.ErrInvalidWire
	}
	state := c.config.Engine.State()
	if state.SessionEpoch != c.epoch || state.AccountClosed {
		return cryptox.IssuerRecoveryProof{}, localstate.ErrLocalSession
	}
	previous := state.Cloud
	if e := v.ValidateStoredIssuerEvidence(previous); e != nil {
		return cryptox.IssuerRecoveryProof{}, e
	}
	p := cloneRecoveryEvidence(*v.initialRecoveryEvidence)
	if len(previous.IssuerEvidence) > 0 {
		var e error
		p, e = decodeRecoveryEvidence(previous.IssuerEvidence)
		if e != nil {
			return p, e
		}
	}
	return p, nil
}

// PrepareEnrollmentProofV4 取已验证当前本机 Admin 的显式选中环境来源。
// recovery proof 不能替代当前权限；暂停或当前数据/授权版本未同步即拒绝。
func (c *Client) PrepareEnrollmentProofV4(environments []string) (cryptox.IssuerRecoveryProof, cryptox.PinnedIssuerRoot, error) {
	var empty cryptox.IssuerRecoveryProof
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.initialRecoveryEvidence == nil || v.evidenceRoot == nil || len(environments) == 0 || len(environments) > 16 {
		return empty, cryptox.PinnedIssuerRoot{}, ErrWritePermission
	}
	state := c.config.Engine.State()
	if state.Paused {
		return empty, cryptox.PinnedIssuerRoot{}, ErrPaused
	}
	p, e := c.CurrentIssuerRecoveryEvidence()
	if e != nil {
		return empty, cryptox.PinnedIssuerRoot{}, e
	}
	proof, e := cryptox.VerifyIssuerRecoveryEvidence(*v.evidenceRoot, p)
	if e != nil {
		return empty, cryptox.PinnedIssuerRoot{}, e
	}
	ts := map[string]string{}
	for _, t := range p.Targets {
		ts[t.EnvironmentID] = t.AuthorityHash
	}
	p.Targets = []cryptox.IssuerTarget{}
	seen := map[string]bool{}
	for _, env := range environments {
		if !enrollmentID.MatchString(env) || seen[env] {
			return empty, cryptox.PinnedIssuerRoot{}, cryptox.ErrInvalidWire
		}
		seen[env] = true
		g, known := proof.Authority(ts[env])
		local, exists := state.Cloud.Environments[env]
		expiry, _ := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
		if !known || !exists || local.Role != localstate.Admin || g.Grant.Role != "admin" || g.Grant.KeyVersion != strconv.FormatUint(local.KeyVersion, 10) || g.Grant.GrantGeneration != strconv.FormatUint(local.GrantGeneration, 10) || expiry != 0 && expiry <= c.config.Now().Unix() || proof.VerifyTarget(g, c.config.DeviceID, cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey), v.receivingPublicKey) != nil {
			return empty, cryptox.PinnedIssuerRoot{}, ErrWritePermission
		}
		p.Targets = append(p.Targets, cryptox.IssuerTarget{EnvironmentID: env, AuthorityHash: ts[env]})
	}
	normalizeRecoveryEvidence(&p)
	if _, e = cryptox.VerifyIssuerRecoveryEvidence(*v.evidenceRoot, p); e != nil {
		return empty, cryptox.PinnedIssuerRoot{}, e
	}
	return p, *v.evidenceRoot, nil
}

// 已验接受序号也是全局持久检查点下界；历史图有效不能替代服务器当前head绑定。
func validateRecoveryLedgerSequence(p cryptox.IssuerRecoveryProof, checkpoint uint64) error {
	if checkpoint > 9007199254740991 || p.Initialization.Sequence == 0 || p.Initialization.Sequence > checkpoint {
		return cryptox.ErrInvalidWire
	}
	for _, r := range p.Transitions {
		if r.Sequence == 0 || r.Sequence > checkpoint {
			return cryptox.ErrInvalidWire
		}
	}
	for _, r := range p.RecoveredDevices {
		if r.Sequence == 0 || r.Sequence > checkpoint {
			return cryptox.ErrInvalidWire
		}
	}
	return nil
}
