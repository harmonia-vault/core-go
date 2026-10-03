package syncclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// 证书5固定原初始化根；后续HTTP来源不能改变它或回退到旧profile。
type IssuerDAGPinnedTrust struct {
	AccountID              string
	AccountGeneration      uint64
	DeviceID               string
	DeviceSigningPublicKey ed25519.PublicKey
	ReceivingPrivateKey    []byte
	Receipt                EnrollmentReceiptV5
	Now                    func() time.Time
}
type RecoveredDAGPinnedTrust struct {
	Trust    PinnedTrust
	Pin      cryptox.PinnedIssuerRoot
	Evidence cryptox.IssuerRecoveryDAG
	Accepted cryptox.AcceptedRecoveredDeviceV2
}

func cloneDAGEvidence(p cryptox.IssuerRecoveryDAG) cryptox.IssuerRecoveryDAG {
	b, _ := json.Marshal(p)
	var out cryptox.IssuerRecoveryDAG
	_ = json.Unmarshal(b, &out)
	return out
}
func dagView(p *cryptox.IssuerRecoveryDAG) (*cryptox.RecoverySourceView, error) {
	if p.Source.Kind == "proof3" && p.Source.View != nil {
		return p.Source.View, nil
	}
	if p.Source.Kind != "proof2" || p.Source.Proof == nil || len(p.Records) != 0 {
		return nil, cryptox.ErrInvalidWire
	}
	old := p.Source.Proof
	h, e := p.Initialization.Hash()
	if e != nil {
		return nil, e
	}
	path := make([]cryptox.IssuerRecoveryArchive, 0, len(old.Path))
	for _, n := range old.Path {
		n := n
		path = append(path, cryptox.IssuerRecoveryArchive{Kind: "paired", Enrollment: &n})
	}
	paths := make([][]cryptox.IssuerRecoveryArchive, 0, len(old.IdentityPaths))
	for _, branch := range old.IdentityPaths {
		b := []cryptox.IssuerRecoveryArchive{}
		for _, n := range branch {
			n := n
			b = append(b, cryptox.IssuerRecoveryArchive{Kind: "paired", Enrollment: &n})
		}
		paths = append(paths, b)
	}
	nodes := make([]cryptox.IssuerRecoveryAuthority, 0, len(old.Authorities))
	for _, n := range old.Authorities {
		nodes = append(nodes, cryptox.IssuerRecoveryAuthority{Grant: n.Grant, ParentHash: n.ParentHash, OriginHash: n.OriginHash, PreviousGrantHash: n.PreviousGrantHash})
	}
	v := &cryptox.RecoverySourceView{Profile: cryptox.RecoverySourceViewProfile, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, InitializationHash: h, TrustRoot: old.TrustRoot, RecoveryHeadHash: h, Path: path, Authorities: nodes, Targets: old.Targets, Origins: old.Origins, IdentityPaths: paths, Dependencies: []cryptox.RecoveryDependency{}}
	p.Source = cryptox.RecoverySource{Kind: "proof3", View: v}
	return v, nil
}
func completedEvidenceV5(r EnrollmentReceiptV5) (cryptox.IssuerRecoveryDAG, error) {
	a := r.Approval
	p := cloneDAGEvidence(a.IssuerProof)
	v, e := dagView(&p)
	if e != nil {
		return p, e
	}
	cert, e := a.Certificate()
	if e != nil {
		return p, e
	}
	node := cryptox.IssuerEnrollment{CertificateVersion: "5", IssuerProofHash: cert.IssuerProofHash, Approval: cryptox.EnrollmentApproval{Context: a.Context, PairingProfile: a.PairingProfile, TranscriptHash: a.TranscriptHash, Grants: a.Grants, ApproverSignature: a.ApproverSignature, InitiatorSignature: a.InitiatorSignature}}
	v.Path = append(v.Path, cryptox.IssuerRecoveryArchive{Kind: "paired", Enrollment: &node})
	parents := map[string]string{}
	for _, t := range v.Targets {
		parents[t.EnvironmentID] = t.AuthorityHash
	}
	v.Targets = []cryptox.IssuerTarget{}
	for _, g := range a.Grants {
		h, e := cryptox.IssuerAuthorityHash(g)
		if e != nil {
			return p, e
		}
		v.Authorities = append(v.Authorities, cryptox.IssuerRecoveryAuthority{Grant: g, ParentHash: parents[g.Grant.EnvironmentID]})
		v.Targets = append(v.Targets, cryptox.IssuerTarget{EnvironmentID: g.Grant.EnvironmentID, AuthorityHash: h})
	}
	normalizeDAG(&p)
	return p, nil
}
func NewPinnedVerifierV5(t IssuerDAGPinnedTrust) (*PinnedVerifier, error) {
	a := t.Receipt.Approval
	p, e := cryptox.VerifyCompletedEnrollmentV5(cryptox.ConfirmedEnrollmentAnchor{Context: a.Context, TranscriptHash: a.TranscriptHash}, a)
	if e != nil {
		return nil, e
	}
	v, e := newIssuerDAGPinnedVerifier(t, p)
	if e == nil {
		v.requireEvidence = true
		v.requireStoredEvidence = true
	}
	return v, e
}
func newIssuerDAGPinnedVerifier(t IssuerDAGPinnedTrust, proof *cryptox.VerifiedRecoveryDAG) (*PinnedVerifier, error) {
	if proof == nil || t.AccountID == "" || t.AccountGeneration == 0 || !enrollmentID.MatchString(t.DeviceID) || !enrollmentID.MatchString(t.Receipt.IdempotencyKey) || len(t.DeviceSigningPublicKey) != 32 {
		return nil, cryptox.ErrInvalidWire
	}
	sk, e := ecdh.X25519().NewPrivateKey(t.ReceivingPrivateKey)
	if e != nil {
		return nil, e
	}
	a := t.Receipt.Approval
	c := a.Context
	recv := cryptox.EncodeBase64(sk.PublicKey().Bytes())
	if c.AccountID != t.AccountID || c.AccountGeneration != strconv.FormatUint(t.AccountGeneration, 10) || c.InitiatorDeviceID != t.DeviceID || c.InitiatorSigningPublicKey != cryptox.EncodeBase64(t.DeviceSigningPublicKey) || c.InitiatorReceivingPublicKey != recv || a.CertificateVersion != "5" {
		return nil, cryptox.ErrInvalidWire
	}
	if t.Now == nil {
		t.Now = time.Now
	}
	initial := cloneDAGEvidence(a.IssuerProof)
	if a.InitiatorSignature != "" {
		initial, e = completedEvidenceV5(t.Receipt)
		if e != nil {
			return nil, e
		}
	}
	root := initial.Initialization.Proposal.Device
	pin := cryptox.PinnedIssuerRoot{AccountID: t.AccountID, AccountGeneration: c.AccountGeneration, DeviceID: root.ID, SigningPublicKey: root.SigningPublicKey, ReceivingPublicKey: root.ReceivingPublicKey}
	if a.InitiatorSignature != "" {
		proof, e = cryptox.VerifyIssuerRecoveryDAG(pin, initial)
		if e != nil {
			return nil, e
		}
	}
	return &PinnedVerifier{trust: PinnedTrust{AccountID: t.AccountID, AccountGeneration: t.AccountGeneration, DeviceID: t.DeviceID, DeviceSigningPublicKey: bytes.Clone(t.DeviceSigningPublicKey), ReceivingPrivateKey: bytes.Clone(t.ReceivingPrivateKey), Now: t.Now}, receivingPublicKey: recv, issuerOriginProof: proof, evidenceRoot: &pin, initialDAGEvidence: &initial, genesisAuthorities: proof.InitialAuthorities()}, nil
}
func NewRecoveredDAGPinnedVerifier(t RecoveredDAGPinnedTrust) (*PinnedVerifier, error) {
	tr := t.Trust
	if len(tr.Managers) != 0 || tr.AccountID == "" || tr.AccountGeneration == 0 || !enrollmentID.MatchString(tr.DeviceID) || len(tr.DeviceSigningPublicKey) != 32 || t.Pin.AccountID != tr.AccountID || t.Pin.AccountGeneration != strconv.FormatUint(tr.AccountGeneration, 10) {
		return nil, cryptox.ErrInvalidWire
	}
	sk, e := ecdh.X25519().NewPrivateKey(tr.ReceivingPrivateKey)
	if e != nil {
		return nil, e
	}
	recv := cryptox.EncodeBase64(sk.PublicKey().Bytes())
	p := cloneDAGEvidence(t.Evidence)
	proof, e := cryptox.VerifyIssuerRecoveryDAG(t.Pin, p)
	if e != nil {
		return nil, e
	}
	own := t.Accepted.Submission.Enrollment
	if t.Accepted.Sequence == 0 || own.AccountID != tr.AccountID || own.AccountGeneration != t.Pin.AccountGeneration || own.DeviceID != tr.DeviceID || own.DeviceSigningPublicKey != cryptox.EncodeBase64(tr.DeviceSigningPublicKey) || own.DeviceReceivingPublicKey != recv {
		return nil, cryptox.ErrInvalidWire
	}
	record := cryptox.RecoveryDAGRecord{Kind: "recovered-v2", RecoveredV2: &t.Accepted}
	ref, e := record.Reference()
	if e != nil {
		return nil, e
	}
	found := false
	for _, r := range p.Records {
		x, e := r.Reference()
		if e != nil {
			return nil, e
		}
		if x == ref {
			if !sameJSON(r, record) {
				return nil, cryptox.ErrInvalidWire
			}
			found = true
		}
	}
	view, e := dagView(&p)
	if e != nil || !found || len(view.Path) != 1 || view.Path[0].Kind != "recovered" || view.Path[0].RecoveryEnrollmentHash != ref.ReferenceHash || len(view.Targets) != len(t.Accepted.Submission.Grants) {
		return nil, cryptox.ErrInvalidWire
	}
	for _, g := range t.Accepted.Submission.Grants {
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
	return &PinnedVerifier{trust: tr, receivingPublicKey: recv, issuerOriginProof: proof, evidenceRoot: &pin, initialDAGEvidence: &p, genesisAuthorities: proof.InitialAuthorities(), requireEvidence: true, requireStoredEvidence: true}, nil
}
func (c *Client) requestDAGPull(ctx context.Context, u *url.URL, out *Pull) error {
	var wire struct {
		IssuerEvidence    *cryptox.IssuerRecoveryDAG `json:"issuerEvidence,omitempty"`
		Scope             string                     `json:"scope,omitempty"`
		EnvironmentEvents []EnvironmentEvent         `json:"environmentEvents,omitempty"`
		AccountID         string                     `json:"accountId"`
		AccountGeneration string                     `json:"accountGeneration"`
		Sequence          uint64                     `json:"sequence"`
		Grants            []SignedGrant              `json:"grants"`
		Events            []Event                    `json:"events"`
	}
	if e := c.request(ctx, http.MethodGet, u, nil, &wire); e != nil {
		return e
	}
	*out = Pull{IssuerDAGEvidence: wire.IssuerEvidence, Scope: wire.Scope, EnvironmentEvents: wire.EnvironmentEvents, AccountID: wire.AccountID, AccountGeneration: wire.AccountGeneration, Sequence: wire.Sequence, Grants: wire.Grants, Events: wire.Events}
	return nil
}
func normalizeDAG(p *cryptox.IssuerRecoveryDAG) {
	v := p.Source.View
	if v == nil {
		return
	}
	sort.Slice(v.Authorities, func(i, j int) bool {
		a, _ := cryptox.IssuerAuthorityHash(v.Authorities[i].Grant)
		b, _ := cryptox.IssuerAuthorityHash(v.Authorities[j].Grant)
		return a < b
	})
	sort.Slice(v.Targets, func(i, j int) bool { return v.Targets[i].EnvironmentID < v.Targets[j].EnvironmentID })
	sort.Slice(v.Origins, func(i, j int) bool {
		a, _ := cryptox.EnvironmentOriginHash(v.Origins[i])
		b, _ := cryptox.EnvironmentOriginHash(v.Origins[j])
		return a < b
	})
	sort.Slice(v.IdentityPaths, func(i, j int) bool {
		a, _ := json.Marshal(v.IdentityPaths[i])
		b, _ := json.Marshal(v.IdentityPaths[j])
		return string(a) < string(b)
	})
	sort.Slice(v.Dependencies, func(i, j int) bool {
		a, b := v.Dependencies[i], v.Dependencies[j]
		return a.Kind < b.Kind || a.Kind == b.Kind && a.ReferenceHash < b.ReferenceHash
	})
	sort.Slice(p.Records, func(i, j int) bool {
		a, _ := p.Records[i].Reference()
		b, _ := p.Records[j].Reference()
		return a.Kind < b.Kind || a.Kind == b.Kind && a.ReferenceHash < b.ReferenceHash
	})
}

// 保存完整已验历史节点，currentTargets来自本次候选；原记录序号和包不能重新分配。
func mergeDAGEvidence(old, candidate cryptox.IssuerRecoveryDAG) (cryptox.IssuerRecoveryDAG, error) {
	out := cloneDAGEvidence(old)
	next := cloneDAGEvidence(candidate)
	if out.AccountID != next.AccountID || out.AccountGeneration != next.AccountGeneration || !sameJSON(out.Initialization, next.Initialization) {
		return out, cryptox.ErrInvalidWire
	}
	a, e := dagView(&out)
	if e != nil {
		return out, e
	}
	b, e := dagView(&next)
	if e != nil {
		return out, e
	}
	a.TrustRoot = b.TrustRoot
	a.RecoveryHeadHash = b.RecoveryHeadHash
	nodes := map[string]cryptox.IssuerRecoveryAuthority{}
	for _, n := range append(a.Authorities, b.Authorities...) {
		h, e := cryptox.IssuerAuthorityHash(n.Grant)
		if e != nil {
			return out, e
		}
		if old, ok := nodes[h]; ok && !sameJSON(old, n) {
			return out, cryptox.ErrInvalidWire
		}
		nodes[h] = n
	}
	a.Authorities = []cryptox.IssuerRecoveryAuthority{}
	for _, n := range nodes {
		a.Authorities = append(a.Authorities, n)
	}
	origins := map[string]cryptox.SignedEnvironmentOrigin{}
	for _, o := range append(a.Origins, b.Origins...) {
		h, e := cryptox.EnvironmentOriginHash(o)
		if e != nil {
			return out, e
		}
		if old, ok := origins[h]; ok && !sameJSON(old, o) {
			return out, cryptox.ErrInvalidWire
		}
		origins[h] = o
	}
	a.Origins = []cryptox.SignedEnvironmentOrigin{}
	for _, o := range origins {
		a.Origins = append(a.Origins, o)
	}
	paths := map[string][]cryptox.IssuerRecoveryArchive{}
	for _, p := range append(append([][]cryptox.IssuerRecoveryArchive{a.Path, b.Path}, a.IdentityPaths...), b.IdentityPaths...) {
		if len(p) > 0 {
			x, _ := json.Marshal(p)
			paths[string(x)] = p
		}
	}
	a.Path = b.Path
	main, _ := json.Marshal(a.Path)
	delete(paths, string(main))
	a.IdentityPaths = [][]cryptox.IssuerRecoveryArchive{}
	for _, p := range paths {
		a.IdentityPaths = append(a.IdentityPaths, p)
	}
	targets := map[string]cryptox.IssuerTarget{}
	for _, t := range append(a.Targets, b.Targets...) {
		targets[t.EnvironmentID] = t
	}
	a.Targets = []cryptox.IssuerTarget{}
	for _, t := range targets {
		a.Targets = append(a.Targets, t)
	}
	records := map[string]cryptox.RecoveryDAGRecord{}
	for _, r := range append(out.Records, next.Records...) {
		ref, e := r.Reference()
		if e != nil {
			return out, e
		}
		if old, ok := records[ref.ReferenceHash]; ok && !sameJSON(old, r) {
			return out, cryptox.ErrInvalidWire
		}
		records[ref.ReferenceHash] = r
	}
	out.Records = []cryptox.RecoveryDAGRecord{}
	for _, r := range records {
		out.Records = append(out.Records, r)
	}
	refs := map[string]bool{}
	if a.RecoveryHeadHash != a.InitializationHash {
		refs[a.RecoveryHeadHash] = true
	}
	for _, p := range append([][]cryptox.IssuerRecoveryArchive{a.Path}, a.IdentityPaths...) {
		for _, n := range p {
			if n.Kind == "recovered" {
				refs[n.RecoveryEnrollmentHash] = true
			}
		}
	}
	for _, n := range a.Authorities {
		if n.RecoveryEnrollmentHash != "" {
			refs[n.RecoveryEnrollmentHash] = true
		}
	}
	a.Dependencies = []cryptox.RecoveryDependency{}
	for h := range refs {
		r, ok := records[h]
		if !ok {
			return out, cryptox.ErrInvalidWire
		}
		ref, _ := r.Reference()
		a.Dependencies = append(a.Dependencies, ref)
	}
	normalizeDAG(&out)
	return out, nil
}
func validateDAGSequence(p cryptox.IssuerRecoveryDAG, checkpoint uint64) error {
	if checkpoint > 9007199254740991 || p.Initialization.Sequence == 0 || p.Initialization.Sequence > checkpoint {
		return cryptox.ErrInvalidWire
	}
	for _, r := range p.Records {
		var seq uint64
		switch r.Kind {
		case "transition-v1":
			seq = r.TransitionV1.Sequence
		case "recovered-v1":
			seq = r.RecoveredV1.Sequence
		case "transition-v2":
			seq = r.TransitionV2.Sequence
		case "recovered-v2":
			seq = r.RecoveredV2.Sequence
		default:
			return cryptox.ErrInvalidWire
		}
		if seq == 0 || seq > checkpoint {
			return cryptox.ErrInvalidWire
		}
	}
	return nil
}
func (v *PinnedVerifier) withIssuerDAGEvidence(pull Pull, previous localstate.CloudSnapshot) (*PinnedVerifier, json.RawMessage, error) {
	if pull.IssuerEvidence != nil || pull.IssuerRecoveryEvidence != nil || v.evidenceRoot == nil {
		return nil, nil, cryptox.ErrInvalidWire
	}
	p := cloneDAGEvidence(*v.initialDAGEvidence)
	prior, e := cryptox.VerifyIssuerRecoveryDAG(*v.evidenceRoot, p)
	if e != nil {
		return nil, nil, e
	}
	if len(previous.IssuerEvidence) > 0 {
		stored, e := cryptox.DecodeIssuerRecoveryDAG(previous.IssuerEvidence)
		if e != nil {
			return nil, nil, e
		}
		prior, e = cryptox.VerifyRecoveryDAGAdvance(prior, stored)
		if e != nil {
			return nil, nil, e
		}
		p = stored
	}
	if pull.IssuerDAGEvidence != nil {
		candidate := *pull.IssuerDAGEvidence
		if _, e = cryptox.VerifyRecoveryDAGAdvance(prior, candidate); e != nil {
			return nil, nil, e
		}
		p, e = mergeDAGEvidence(p, candidate)
		if e != nil {
			return nil, nil, e
		}
	} else if v.requireEvidence {
		for _, g := range pull.Grants {
			expiry, _ := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
			if g.Grant.Role != "none" && (expiry == 0 || expiry > v.trust.Now().Unix()) {
				return nil, nil, errors.New("active grants require explicit issuer DAG evidence")
			}
		}
	}
	if !v.requireEvidence && len(previous.IssuerEvidence) == 0 && pull.IssuerDAGEvidence == nil {
		return v, nil, nil
	}
	proof, e := cryptox.VerifyRecoveryDAGAdvance(prior, p)
	if e != nil {
		return nil, nil, e
	}
	if pull.IssuerDAGEvidence != nil {
		for _, g := range pull.Grants {
			expiry, _ := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
			if g.Grant.Role != "none" && (expiry == 0 || expiry > v.trust.Now().Unix()) {
				if e = proof.VerifyTarget(cryptox.SignedGrantWire{Grant: g.Grant, Signature: g.Signature}, v.trust.DeviceID, cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey), v.receivingPublicKey); e != nil {
					return nil, nil, e
				}
			}
		}
	}
	if e = validateDAGSequence(p, pull.Sequence); e != nil {
		return nil, nil, e
	}
	encoded, e := json.Marshal(p)
	if e != nil || len(encoded) > cryptox.MaxRecoveryAuthorityBytes {
		return nil, nil, cryptox.ErrInvalidWire
	}
	out := *v
	out.issuerOriginProof = proof
	return &out, encoded, nil
}
func (v *PinnedVerifier) cachedDAGLedger(data []byte) (*cachedSourceLedger, error) {
	p, e := cryptox.DecodeIssuerRecoveryDAG(data)
	if e != nil {
		return nil, e
	}
	view, e := dagView(&p)
	if e != nil {
		return nil, e
	}
	l := &cachedSourceLedger{proof: v.issuerOriginProof, rights: map[string]cryptox.IssuerAuthorityV2{}, origins: map[string]cryptox.SignedEnvironmentOrigin{}, targets: map[string]string{}}
	for _, n := range view.Authorities {
		h, e := cryptox.IssuerAuthorityHash(n.Grant)
		if e != nil {
			return nil, e
		}
		l.rights[h] = cryptox.IssuerAuthorityV2{Grant: n.Grant, ParentHash: n.ParentHash, OriginHash: n.OriginHash, PreviousGrantHash: n.PreviousGrantHash}
	}
	for _, o := range view.Origins {
		h, e := cryptox.EnvironmentOriginHash(o)
		if e != nil {
			return nil, e
		}
		l.origins[h] = o
	}
	for _, t := range view.Targets {
		l.targets[t.EnvironmentID] = t.AuthorityHash
	}
	return l, nil
}
func (v *PinnedVerifier) validateStoredDAGEvidence(previous localstate.CloudSnapshot) error {
	if previous.AccountID != "" && (previous.AccountID != v.trust.AccountID || previous.AccountGeneration != v.trust.AccountGeneration) {
		return cryptox.ErrInvalidWire
	}
	if len(previous.IssuerEvidence) == 0 {
		if previous.AccountID == "" && previous.Sequence == 0 && previous.AuthorizationSequence == 0 && len(previous.Environments) == 0 {
			return nil
		}
		return errors.New("cert5 cached state requires protected issuer DAG ledger")
	}
	p, e := cryptox.DecodeIssuerRecoveryDAG(previous.IssuerEvidence)
	if e != nil {
		return e
	}
	initial, e := cryptox.VerifyIssuerRecoveryDAG(*v.evidenceRoot, *v.initialDAGEvidence)
	if e != nil {
		return e
	}
	proof, e := cryptox.VerifyRecoveryDAGAdvance(initial, p)
	if e != nil {
		return e
	}
	if previous.AccountID != v.trust.AccountID || previous.AccountGeneration != v.trust.AccountGeneration {
		return cryptox.ErrInvalidWire
	}
	checkpoint := previous.Sequence
	if checkpoint < previous.AuthorizationSequence {
		checkpoint = previous.AuthorizationSequence
	}
	if e = validateDAGSequence(p, checkpoint); e != nil {
		return e
	}
	clone := *v
	clone.issuerOriginProof = proof
	l, e := clone.cachedDAGLedger(previous.IssuerEvidence)
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
func (c *Client) CurrentIssuerDAGEvidence() (cryptox.IssuerRecoveryDAG, error) {
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.initialDAGEvidence == nil {
		return cryptox.IssuerRecoveryDAG{}, cryptox.ErrInvalidWire
	}
	state := c.config.Engine.State()
	if state.SessionEpoch != c.epoch || state.AccountClosed {
		return cryptox.IssuerRecoveryDAG{}, localstate.ErrLocalSession
	}
	if e := v.ValidateStoredIssuerEvidence(state.Cloud); e != nil {
		return cryptox.IssuerRecoveryDAG{}, e
	}
	if len(state.Cloud.IssuerEvidence) > 0 {
		return cryptox.DecodeIssuerRecoveryDAG(state.Cloud.IssuerEvidence)
	}
	return cloneDAGEvidence(*v.initialDAGEvidence), nil
}
func (c *Client) PrepareEnrollmentProofV5(environments []string) (cryptox.IssuerRecoveryDAG, cryptox.PinnedIssuerRoot, error) {
	var empty cryptox.IssuerRecoveryDAG
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.initialDAGEvidence == nil || v.evidenceRoot == nil || len(environments) == 0 || len(environments) > 16 {
		return empty, cryptox.PinnedIssuerRoot{}, ErrWritePermission
	}
	state := c.config.Engine.State()
	if state.Paused {
		return empty, cryptox.PinnedIssuerRoot{}, ErrPaused
	}
	p, e := c.CurrentIssuerDAGEvidence()
	if e != nil {
		return empty, cryptox.PinnedIssuerRoot{}, e
	}
	proof, e := cryptox.VerifyIssuerRecoveryDAG(*v.evidenceRoot, p)
	if e != nil {
		return empty, cryptox.PinnedIssuerRoot{}, e
	}
	view, e := dagView(&p)
	if e != nil {
		return empty, cryptox.PinnedIssuerRoot{}, e
	}
	ts := map[string]string{}
	for _, t := range view.Targets {
		ts[t.EnvironmentID] = t.AuthorityHash
	}
	view.Targets = []cryptox.IssuerTarget{}
	seen := map[string]bool{}
	for _, id := range environments {
		if !enrollmentID.MatchString(id) || seen[id] {
			return empty, cryptox.PinnedIssuerRoot{}, cryptox.ErrInvalidWire
		}
		seen[id] = true
		g, known := proof.Authority(ts[id])
		local, exists := state.Cloud.Environments[id]
		expiry, _ := strconv.ParseInt(g.Grant.ExpiresAt, 10, 64)
		if !known || !exists || local.Role != localstate.Admin || g.Grant.Role != "admin" || g.Grant.KeyVersion != strconv.FormatUint(local.KeyVersion, 10) || g.Grant.GrantGeneration != strconv.FormatUint(local.GrantGeneration, 10) || expiry != 0 && expiry <= c.config.Now().Unix() || proof.VerifyTarget(g, c.config.DeviceID, cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey), v.receivingPublicKey) != nil {
			return empty, cryptox.PinnedIssuerRoot{}, ErrWritePermission
		}
		view.Targets = append(view.Targets, cryptox.IssuerTarget{EnvironmentID: id, AuthorityHash: ts[id]})
	}
	normalizeDAG(&p)
	if _, e = cryptox.VerifyIssuerRecoveryDAG(*v.evidenceRoot, p); e != nil {
		return empty, cryptox.PinnedIssuerRoot{}, e
	}
	return p, *v.evidenceRoot, nil
}
