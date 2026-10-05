package cryptox

import (
	"encoding/json"
	"reflect"
)

// EnrollmentApprovalV5 只由明确共同 issuer-recovery-dag-v1 的端点使用。
type EnrollmentApprovalV5 struct {
	CertificateVersion string            `json:"certificateVersion"`
	Capabilities       []string          `json:"capabilities"`
	Context            EnrollmentContext `json:"context"`
	PairingProfile     string            `json:"pairingProfile"`
	TranscriptHash     string            `json:"transcriptHash"`
	Grants             []SignedGrantWire `json:"grants"`
	IssuerProof        IssuerRecoveryDAG `json:"issuerProof"`
	ApproverSignature  string            `json:"approverSignature"`
	InitiatorSignature string            `json:"initiatorSignature,omitempty"`
}

func (a EnrollmentApprovalV5) Certificate() (EnrollmentCertificateV5, error) {
	if a.CertificateVersion != "5" || len(a.Capabilities) != 1 || a.Capabilities[0] != RecoveryDAGCapability {
		return EnrollmentCertificateV5{}, ErrInvalidWire
	}
	base, e := (EnrollmentApproval{a.Context, a.PairingProfile, a.TranscriptHash, a.Grants, a.ApproverSignature, a.InitiatorSignature}).Certificate()
	if e != nil {
		return EnrollmentCertificateV5{}, e
	}
	h, e := a.IssuerProof.Hash()
	if e != nil {
		return EnrollmentCertificateV5{}, e
	}
	return EnrollmentCertificateV5{base, h}, nil
}
func verifyEnrollmentApprovalV5(anchor ConfirmedEnrollmentAnchor, a EnrollmentApprovalV5, complete bool) (*VerifiedRecoveryDAG, error) {
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
	r, e := sourceRoot(p.Source)
	if e != nil {
		return nil, e
	}
	v, e := VerifyIssuerRecoveryDAG(PinnedIssuerRoot{p.AccountID, p.AccountGeneration, r.RootDeviceID, r.RootSigningPublicKey, r.RootReceivingPublicKey}, p)
	if e != nil {
		return nil, e
	}
	current := issuerIdentity{r.RootDeviceID, r.RootSigningPublicKey, r.RootReceivingPublicKey}
	if p.AccountID != a.Context.AccountID || p.AccountGeneration != a.Context.AccountGeneration {
		return nil, ErrInvalidSignature
	}
	path := p.Source.View.Path
	if len(path) > 0 {
		last := path[len(path)-1]
		if last.Kind == "paired" {
			x := last.Enrollment.Approval.Context
			current = issuerIdentity{x.InitiatorDeviceID, x.InitiatorSigningPublicKey, x.InitiatorReceivingPublicKey}
		} else {
			rec, ok := v.recovered[last.RecoveryEnrollmentHash]
			if !ok {
				return nil, ErrInvalidSignature
			}
			current = issuerIdentity{rec.deviceID, rec.signingPublic, rec.receivingPublic}
		}
	}
	if !issuerIdentityMatches(current, a.Context.ApproverDeviceID, a.Context.ApproverSigningPublicKey, a.Context.ApproverReceivingPublicKey) {
		return nil, ErrInvalidSignature
	}
	if _, known := v.graph.identities[a.Context.InitiatorDeviceID]; known {
		return nil, ErrInvalidWire
	}
	for _, pub := range []string{a.Context.InitiatorSigningPublicKey, a.Context.InitiatorReceivingPublicKey} {
		if v.publicOwners[pub] != "" {
			return nil, ErrInvalidWire
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
	if len(v.graph.targets) != len(a.Grants) {
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
func VerifyEnrollmentApprovalV5(a ConfirmedEnrollmentAnchor, r EnrollmentApprovalV5) (*VerifiedRecoveryDAG, error) {
	return verifyEnrollmentApprovalV5(a, r, false)
}
func VerifyCompletedEnrollmentV5(a ConfirmedEnrollmentAnchor, r EnrollmentApprovalV5) (*VerifiedRecoveryDAG, error) {
	return verifyEnrollmentApprovalV5(a, r, true)
}
func pairedRecoveryPathForDAG(nodes []IssuerEnrollment) []IssuerRecoveryArchive {
	out := make([]IssuerRecoveryArchive, 0, len(nodes))
	for _, n := range nodes {
		x := n
		out = append(out, IssuerRecoveryArchive{Kind: "paired", Enrollment: &x})
	}
	return out
}
func DecodeEnrollmentApprovalV5(data []byte) (EnrollmentApprovalV5, error) {
	var a EnrollmentApprovalV5
	m, e := strictDAGObjectOptional(data, []string{"certificateVersion", "capabilities", "context", "pairingProfile", "transcriptHash", "grants", "issuerProof", "approverSignature"}, []string{"initiatorSignature"})
	if e != nil {
		return a, e
	}
	proof, e := DecodeIssuerRecoveryDAG(m["issuerProof"])
	if e != nil {
		return a, e
	}
	type base struct {
		CertificateVersion string            `json:"certificateVersion"`
		Capabilities       []string          `json:"capabilities"`
		Context            EnrollmentContext `json:"context"`
		PairingProfile     string            `json:"pairingProfile"`
		TranscriptHash     string            `json:"transcriptHash"`
		Grants             []SignedGrantWire `json:"grants"`
		ApproverSignature  string            `json:"approverSignature"`
		InitiatorSignature string            `json:"initiatorSignature,omitempty"`
	}
	delete(m, "issuerProof")
	raw, e := json.Marshal(m)
	if e != nil {
		return a, ErrInvalidWire
	}
	var b base
	if validateRecoveryJSONShape(raw, reflect.TypeOf(b), nil) != nil || strictDAGDecode(raw, &b) != nil {
		return a, ErrInvalidWire
	}
	a = EnrollmentApprovalV5{b.CertificateVersion, b.Capabilities, b.Context, b.PairingProfile, b.TranscriptHash, b.Grants, proof, b.ApproverSignature, b.InitiatorSignature}
	_, e = a.Certificate()
	return a, e
}
