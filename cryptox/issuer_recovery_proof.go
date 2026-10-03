package cryptox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
)

const (
	IssuerRecoveryProfile   = "harmonia/issuer-proof/v3"
	MaxIssuerRecoveryRights = 1024
	MaxIssuerRecoveryPaths  = 32
	MaxIssuerRecoveryNodes  = 256
)

// IssuerRecoveryArchive 的显式 kind 不能把恢复来源伪装成原根设备签名。
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
	Profile           string                       `json:"profile"`
	AccountID         string                       `json:"accountId"`
	AccountGeneration string                       `json:"accountGeneration"`
	TrustRoot         TrustRoot                    `json:"trustRoot"`
	Initialization    OriginalInitialization       `json:"initialization"`
	Path              []IssuerRecoveryArchive      `json:"path"`
	Authorities       []IssuerRecoveryAuthority    `json:"authorities"`
	Targets           []IssuerTarget               `json:"targets"`
	Origins           []SignedEnvironmentOrigin    `json:"origins"`
	IdentityPaths     [][]IssuerRecoveryArchive    `json:"identityPaths"`
	Transitions       []AcceptedRecoveryTransition `json:"transitions"`
	RecoveredDevices  []AcceptedRecoveredDevice    `json:"recoveredDevices"`
}
type EnrollmentCertificateV4 struct {
	EnrollmentCertificate
	IssuerProofHash string `json:"issuerProofHash"`
}

func (c EnrollmentCertificateV4) SigningBytes() ([]byte, error) {
	b, e := (EnrollmentCertificateV2{c.EnrollmentCertificate, c.IssuerProofHash}).SigningBytes()
	if e != nil {
		return nil, e
	}
	var f []string
	if e = json.Unmarshal(b, &f); e != nil {
		return nil, e
	}
	f[0] = "harmonia/device-enrollment/v4"
	return json.Marshal(f)
}
func SignEnrollmentCertificateV4(c EnrollmentCertificateV4, key ed25519.PrivateKey) (string, error) {
	b, e := c.SigningBytes()
	if e != nil {
		return "", e
	}
	if len(key) != ed25519.PrivateKeySize {
		return "", ErrInvalidWire
	}
	pub := EncodeBase64(key.Public().(ed25519.PublicKey))
	if pub != c.ApproverSigningPublicKey && pub != c.InitiatorSigningPublicKey {
		return "", ErrInvalidSignature
	}
	return signRecoveryPurpose(key, pub, b)
}
func issuerRecoveryArchiveBytes(n IssuerEnrollment) ([]byte, error) {
	if n.CertificateVersion == "4" {
		c, e := n.Approval.Certificate()
		if e != nil {
			return nil, e
		}
		return (EnrollmentCertificateV4{c, n.IssuerProofHash}).SigningBytes()
	}
	return issuerArchiveBytesV2(n)
}
func issuerRecoveryPathRows(path []IssuerRecoveryArchive) ([][]string, error) {
	if path == nil || len(path) > MaxIssuerProofPath {
		return nil, ErrInvalidWire
	}
	rows := make([][]string, 0, len(path))
	for i, n := range path {
		switch n.Kind {
		case "paired":
			if n.Enrollment == nil || n.RecoveryEnrollmentHash != "" {
				return nil, ErrInvalidWire
			}
			b, e := issuerRecoveryArchiveBytes(*n.Enrollment)
			if e != nil {
				return nil, e
			}
			for _, s := range []string{n.Enrollment.Approval.ApproverSignature, n.Enrollment.Approval.InitiatorSignature} {
				if _, e = DecodeBase64(s, 64, 64); e != nil {
					return nil, e
				}
			}
			rows = append(rows, []string{"paired", n.Enrollment.CertificateVersion, EncodeBase64(b), n.Enrollment.Approval.ApproverSignature, n.Enrollment.Approval.InitiatorSignature})
		case "recovered":
			if i != 0 || n.Enrollment != nil || !tokenHashPattern.MatchString(n.RecoveryEnrollmentHash) {
				return nil, ErrInvalidWire
			}
			rows = append(rows, []string{"recovered", n.RecoveryEnrollmentHash})
		default:
			return nil, ErrInvalidWire
		}
	}
	return rows, nil
}
func (p IssuerRecoveryProof) CanonicalBytes() ([]byte, error) {
	if p.Path == nil || p.Authorities == nil || p.Targets == nil || p.Origins == nil || p.IdentityPaths == nil || p.Transitions == nil || p.RecoveredDevices == nil || len(p.Transitions) > MaxRecoveryTransitions || len(p.RecoveredDevices) > MaxRecoveryTransitions {
		return nil, ErrInvalidWire
	}
	if p.Profile != IssuerRecoveryProfile || validID(p.AccountID) != nil || validDecimal(p.AccountGeneration, true) != nil || len(p.Authorities) < 1 || len(p.Authorities) > MaxIssuerRecoveryRights || len(p.Targets) > 256 || len(p.Origins) > MaxIssuerOrigins || len(p.IdentityPaths) > MaxIssuerRecoveryPaths {
		return nil, ErrInvalidWire
	}
	root, e := p.TrustRoot.SigningBytes(p.AccountID, p.AccountGeneration)
	if e != nil {
		return nil, e
	}
	if _, e = DecodeBase64(p.TrustRoot.Signature, 64, 64); e != nil {
		return nil, e
	}
	paths, e := issuerRecoveryPathRows(p.Path)
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
		r, e := issuerRecoveryPathRows(path)
		if e != nil {
			return nil, e
		}
		b, _ := json.Marshal(r)
		branches = append(branches, branch{r, string(b)})
	}
	if total > MaxIssuerRecoveryNodes {
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
	as := append([]IssuerRecoveryAuthority(nil), p.Authorities...)
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
		for _, h := range []string{a.ParentHash, a.OriginHash, a.PreviousGrantHash, a.RecoveryEnrollmentHash} {
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
		rows = append(rows, []string{g.EnvironmentID, g.SubjectDeviceID, g.GrantGeneration, EncodeBase64(b), a.Grant.Signature, a.ParentHash, a.OriginHash, a.PreviousGrantHash, a.RecoveryEnrollmentHash})
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
	ih, e := p.Initialization.Hash()
	if e != nil {
		return nil, e
	}
	ip, e := p.Initialization.proposalBytes()
	if e != nil {
		return nil, e
	}
	iq, e := p.Initialization.Proof.SigningBytes()
	if e != nil {
		return nil, e
	}
	initialization := []string{ih, EncodeBase64(ip), EncodeBase64(iq), p.Initialization.DeviceSignature, p.Initialization.RecoverySignature, "1"}
	transitions := make([][]string, 0, len(p.Transitions))
	recovered := make([][]string, 0, len(p.RecoveredDevices))
	for _, r := range p.Transitions {
		h, e := RecoveryTransitionHash(r.Submission)
		if e != nil {
			return nil, e
		}
		b, e := r.Submission.Transition.SigningBytes()
		if e != nil {
			return nil, e
		}
		transitions = append(transitions, []string{h, EncodeBase64(b), r.Submission.AuthorizationSignature, r.Submission.NewRecoverySignature, strconv.FormatUint(r.Sequence, 10)})
	}
	for _, r := range p.RecoveredDevices {
		h, e := RecoveredDeviceReferenceHash(r.Submission)
		if e != nil {
			return nil, e
		}
		b, e := r.Submission.Enrollment.SigningBytes()
		if e != nil {
			return nil, e
		}
		recovered = append(recovered, []string{h, EncodeBase64(b), r.Submission.RecoverySignature, r.Submission.DeviceSignature, strconv.FormatUint(r.Sequence, 10)})
	}
	for _, rows := range [][][]string{transitions, recovered} {
		sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
		for i := 1; i < len(rows); i++ {
			if rows[i-1][0] == rows[i][0] {
				return nil, ErrInvalidWire
			}
		}
	}
	full, e := json.Marshal(p)
	if e != nil || len(full) > MaxRecoveryAuthorityBytes {
		return nil, ErrInvalidWire
	}
	b, e := json.Marshal([]any{IssuerRecoveryProfile, p.AccountID, p.AccountGeneration, []string{EncodeBase64(root), p.TrustRoot.Signature}, initialization, paths, rows, targets, origins, branchRows, transitions, recovered})
	if e != nil || len(b) > MaxRecoveryAuthorityBytes {
		return nil, ErrInvalidWire
	}
	return b, nil
}

func (p IssuerRecoveryProof) Hash() (string, error) {
	b, e := p.CanonicalBytes()
	if e != nil {
		return "", e
	}
	return hashCanonical(json.RawMessage(b))
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

// pin 只能来自本地确认的受保护回执或完整恢复码验证的同一原 root。
func VerifyIssuerRecoveryEvidence(pin PinnedIssuerRoot, p IssuerRecoveryProof) (*VerifiedIssuerRecoveryProof, error) {
	if _, e := p.CanonicalBytes(); e != nil {
		return nil, e
	}
	authority, e := VerifyRecoveryInitialization(pin, p.Initialization)
	if e != nil {
		return nil, e
	}
	heads := map[string]*VerifiedRecoveryAuthority{authority.HeadHash(): authority}
	transitions := append([]AcceptedRecoveryTransition(nil), p.Transitions...)
	sort.Slice(transitions, func(i, j int) bool { return transitions[i].Sequence < transitions[j].Sequence })
	for _, r := range transitions {
		authority, e = VerifyAcceptedRecoveryTransition(authority, r)
		if e != nil {
			return nil, e
		}
		heads[authority.HeadHash()] = authority
	}
	root := p.TrustRoot
	if !recoveryRootMatches(pin, root) || root.RecoveryGeneration != authority.Generation() || root.RecoverySigningPublicKey != authority.SigningPublicKey() || root.RecoveryReceivingPublicKey != authority.ReceivingPublicKey() {
		return nil, ErrInvalidSignature
	}
	pub, e := DecodeBase64(authority.SigningPublicKey(), 32, 32)
	if e != nil {
		return nil, e
	}
	if e = VerifyTrustRoot(p.AccountID, p.AccountGeneration, root, pub); e != nil {
		return nil, e
	}
	if p.AccountID != pin.AccountID || p.AccountGeneration != pin.AccountGeneration {
		return nil, ErrInvalidSignature
	}
	recovered := map[string]*VerifiedRecoveredDevice{}
	for _, r := range p.RecoveredDevices {
		a, ok := heads[r.Submission.Enrollment.RecoveryTransitionHash]
		if !ok {
			return nil, ErrInvalidSignature
		}
		d, e := VerifyAcceptedRecoveredDevice(a, r)
		if e != nil {
			return nil, e
		}
		if _, ok := recovered[d.referenceHash]; ok {
			return nil, ErrInvalidWire
		}
		recovered[d.referenceHash] = d
	}
	recoveredGrants := make([][]SignedGrantWire, 0, len(p.RecoveredDevices))
	for _, record := range p.RecoveredDevices {
		recoveredGrants = append(recoveredGrants, record.Submission.Grants)
	}
	return verifyRecoverySourceGraph(pin, authority, p, recovered, recoveredGrants, issuerRecoveryArchiveBytes)
}
func DecodeIssuerRecoveryProof(data []byte) (IssuerRecoveryProof, error) {
	var p IssuerRecoveryProof
	if e := validateRecoveryJSONShape(data, reflect.TypeOf(p), map[string]bool{
		"$.transitions[].submission.issuerEvidence": true, "$.transitions[].submission.legacyState": true,
	}); e != nil {
		return p, e
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(&p); e != nil {
		return p, ErrInvalidWire
	}
	var rest any
	if e := d.Decode(&rest); e != io.EOF {
		return p, ErrInvalidWire
	}
	_, e := p.CanonicalBytes()
	return p, e
}

// EnrollmentApprovalV4 只由明确共同 issuer-recovery-v1 的端点使用。
type EnrollmentApprovalV4 struct {
	CertificateVersion string              `json:"certificateVersion"`
	Capabilities       []string            `json:"capabilities"`
	Context            EnrollmentContext   `json:"context"`
	PairingProfile     string              `json:"pairingProfile"`
	TranscriptHash     string              `json:"transcriptHash"`
	Grants             []SignedGrantWire   `json:"grants"`
	IssuerProof        IssuerRecoveryProof `json:"issuerProof"`
	ApproverSignature  string              `json:"approverSignature"`
	InitiatorSignature string              `json:"initiatorSignature,omitempty"`
}

func (a EnrollmentApprovalV4) Certificate() (EnrollmentCertificateV4, error) {
	if a.CertificateVersion != "4" || len(a.Capabilities) != 1 || a.Capabilities[0] != RecoveryAuthorityCapability {
		return EnrollmentCertificateV4{}, ErrInvalidWire
	}
	base, e := (EnrollmentApproval{a.Context, a.PairingProfile, a.TranscriptHash, a.Grants, a.ApproverSignature, a.InitiatorSignature}).Certificate()
	if e != nil {
		return EnrollmentCertificateV4{}, e
	}
	h, e := a.IssuerProof.Hash()
	if e != nil {
		return EnrollmentCertificateV4{}, e
	}
	return EnrollmentCertificateV4{base, h}, nil
}
func verifyEnrollmentApprovalV4(anchor ConfirmedEnrollmentAnchor, a EnrollmentApprovalV4, complete bool) (*VerifiedIssuerRecoveryProof, error) {
	if anchor.Context != a.Context || anchor.TranscriptHash != a.TranscriptHash || issuerHistoricalContext(a.Context) != nil {
		return nil, ErrInvalidWire
	}
	c, e := a.Certificate()
	if e != nil {
		return nil, e
	}
	b, e := c.SigningBytes()
	if e != nil {
		return nil, e
	}
	pub, e := DecodeBase64(anchor.Context.ApproverSigningPublicKey, 32, 32)
	if e != nil {
		return nil, e
	}
	if e = verify(pub, b, a.ApproverSignature); e != nil {
		return nil, e
	}
	if complete || a.InitiatorSignature != "" {
		pub, e := DecodeBase64(anchor.Context.InitiatorSigningPublicKey, 32, 32)
		if e != nil {
			return nil, e
		}
		if e = verify(pub, b, a.InitiatorSignature); e != nil {
			return nil, e
		}
	}
	// 当前 PAKE 管理者先签完整 proof，再由该签名认证其中原根声明。
	// 此局部推导不得替代后续 candidate ledger 的既有受保护 root pin。
	p := a.IssuerProof
	r := p.TrustRoot
	v, e := VerifyIssuerRecoveryEvidence(PinnedIssuerRoot{p.AccountID, p.AccountGeneration, r.RootDeviceID, r.RootSigningPublicKey, r.RootReceivingPublicKey}, p)
	if e != nil {
		return nil, e
	}
	current := issuerIdentity{r.RootDeviceID, r.RootSigningPublicKey, r.RootReceivingPublicKey}
	if len(p.Path) > 0 {
		last := p.Path[len(p.Path)-1]
		if last.Kind == "paired" {
			x := last.Enrollment.Approval.Context
			current = issuerIdentity{x.InitiatorDeviceID, x.InitiatorSigningPublicKey, x.InitiatorReceivingPublicKey}
		} else {
			for _, rec := range p.RecoveredDevices {
				h, _ := RecoveredDeviceReferenceHash(rec.Submission)
				if h == last.RecoveryEnrollmentHash {
					x := rec.Submission.Enrollment
					current = issuerIdentity{x.DeviceID, x.DeviceSigningPublicKey, x.DeviceReceivingPublicKey}
					break
				}
			}
		}
	}
	if !issuerIdentityMatches(current, a.Context.ApproverDeviceID, a.Context.ApproverSigningPublicKey, a.Context.ApproverReceivingPublicKey) {
		return nil, ErrInvalidSignature
	}
	if _, known := v.graph.identities[a.Context.InitiatorDeviceID]; known {
		return nil, ErrInvalidWire
	}
	for _, identity := range v.graph.identities {
		for _, pub := range []string{a.Context.InitiatorSigningPublicKey, a.Context.InitiatorReceivingPublicKey} {
			if pub == identity.signing || pub == identity.receiving || v.recovery.usedRecoveryKeys[pub] {
				return nil, ErrInvalidWire
			}
		}
	}
	v.graph.identities[a.Context.InitiatorDeviceID] = issuerIdentity{a.Context.InitiatorDeviceID, a.Context.InitiatorSigningPublicKey, a.Context.InitiatorReceivingPublicKey}
	approver, e := DecodeBase64(a.Context.ApproverSigningPublicKey, 32, 32)
	if e != nil {
		return nil, e
	}
	if e = VerifyEnrollmentGrants(c.EnrollmentCertificate, a.Grants, approver); e != nil {
		return nil, e
	}
	if len(p.Targets) != len(a.Grants) {
		return nil, ErrInvalidWire
	}
	for _, s := range a.Grants {
		h, ok := v.graph.targets[s.Grant.EnvironmentID]
		parent, known := v.graph.Authority(h)
		g := parent.Grant
		if !ok || !known || g.Role != "admin" || g.SubjectDeviceID != current.id || g.SubjectSigningPublicKey != current.signing || g.SubjectReceivingPublicKey != current.receiving || v.graph.VerifyDelegatedGrant(s, h) != nil {
			return nil, ErrInvalidSignature
		}
	}
	return v, nil
}
func VerifyEnrollmentApprovalV4(a ConfirmedEnrollmentAnchor, r EnrollmentApprovalV4) (*VerifiedIssuerRecoveryProof, error) {
	return verifyEnrollmentApprovalV4(a, r, false)
}
func VerifyCompletedEnrollmentV4(a ConfirmedEnrollmentAnchor, r EnrollmentApprovalV4) (*VerifiedIssuerRecoveryProof, error) {
	return verifyEnrollmentApprovalV4(a, r, true)
}
func DecodeEnrollmentApprovalV4(data []byte) (EnrollmentApprovalV4, error) {
	var a EnrollmentApprovalV4
	if e := validateRecoveryJSONShape(data, reflect.TypeOf(a), map[string]bool{"$.issuerProof.transitions[].submission.issuerEvidence": true, "$.issuerProof.transitions[].submission.legacyState": true}); e != nil {
		return a, e
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(&a); e != nil {
		return a, ErrInvalidWire
	}
	var rest any
	if e := d.Decode(&rest); e != io.EOF {
		return a, ErrInvalidWire
	}
	_, e := a.Certificate()
	return a, e
}
