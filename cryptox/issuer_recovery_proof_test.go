package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type issuerRecoveryFixture struct {
	Recovery              recoveryAuthorityFixture `json:"recovery"`
	Proof                 IssuerRecoveryProof      `json:"proof"`
	CanonicalHex          string                   `json:"canonicalHex"`
	Hash                  string                   `json:"hash"`
	CertificateSigningHex string                   `json:"certificateSigningHex"`
	SyntheticChildEdSeed  string                   `json:"syntheticChildEdSeedHex"`
}

func pairedRecoveryPath(nodes []IssuerEnrollment) []IssuerRecoveryArchive {
	out := make([]IssuerRecoveryArchive, 0, len(nodes))
	for _, n := range nodes {
		x := n
		out = append(out, IssuerRecoveryArchive{Kind: "paired", Enrollment: &x})
	}
	return out
}
func makeIssuerRecoveryFixture(t *testing.T) issuerRecoveryFixture {
	t.Helper()
	f := makeRecoveryAuthorityFixture(t)
	s := f.Device.Submission
	prior := s.IssuerEvidence
	er, e := RecoveredDeviceReferenceHash(s)
	recoveryCheck(t, e)
	p := IssuerRecoveryProof{Profile: IssuerRecoveryProfile, AccountID: f.RootPin.AccountID, AccountGeneration: f.RootPin.AccountGeneration, TrustRoot: prior.TrustRoot, Initialization: f.Original,
		Path: []IssuerRecoveryArchive{{Kind: "recovered", RecoveryEnrollmentHash: er}}, Authorities: []IssuerRecoveryAuthority{}, Targets: []IssuerTarget{}, Origins: prior.Origins, IdentityPaths: [][]IssuerRecoveryArchive{}, Transitions: []AcceptedRecoveryTransition{f.OldCode}, RecoveredDevices: []AcceptedRecoveredDevice{f.Device}}
	for _, a := range prior.Authorities {
		p.Authorities = append(p.Authorities, IssuerRecoveryAuthority{Grant: a.Grant, ParentHash: a.ParentHash, OriginHash: a.OriginHash, PreviousGrantHash: a.PreviousGrantHash})
	}
	if len(prior.Path) > 0 {
		p.IdentityPaths = append(p.IdentityPaths, pairedRecoveryPath(prior.Path))
	}
	for _, path := range prior.IdentityPaths {
		p.IdentityPaths = append(p.IdentityPaths, pairedRecoveryPath(path))
	}
	eg := s.Grants[0]
	eh, e := IssuerAuthorityHash(eg)
	recoveryCheck(t, e)
	p.Authorities = append(p.Authorities, IssuerRecoveryAuthority{Grant: eg, RecoveryEnrollmentHash: er})
	p.Targets = append(p.Targets, IssuerTarget{eg.Grant.EnvironmentID, eh})
	v, e := VerifyIssuerRecoveryEvidence(f.RootPin, p)
	recoveryCheck(t, e)
	recoveryCheck(t, v.VerifyTarget(eg, s.Enrollment.DeviceID, s.Enrollment.DeviceSigningPublicKey, s.Enrollment.DeviceReceivingPublicKey))
	// 这里只验证真实 Ed/HPKE 与历史证明。PAKE transport 的运行另由端到端验收负责。
	parent := ed25519.NewKeyFromSeed(mustHex(t, f.SyntheticSeeds["deviceEd"]))
	child := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	recv, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	recoveryCheck(t, e)
	g := eg.Grant
	g.IssuerDeviceID = eg.Grant.SubjectDeviceID
	g.SubjectDeviceID = "paired-after-recovery-F"
	g.SubjectSigningPublicKey = EncodeBase64(child.Public().(ed25519.PublicKey))
	g.SubjectReceivingPublicKey = EncodeBase64(recv.PublicKey().Bytes())
	g.Role = "ro"
	g.IdempotencyKey = "recovered-approves-F"
	packet, e := WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey})
	recoveryCheck(t, e)
	g.Envelope = EncodeBase64(packet)
	gs, e := SignGrant(g, parent)
	recoveryCheck(t, e)
	context := EnrollmentContext{Purpose: "enroll-device", AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, SessionID: "pair-recovered-F", ChallengeNonce: EncodeBase64(bytes.Repeat([]byte{79}, 32)), ExpiresAt: "2030000100", InitiatorDeviceID: g.SubjectDeviceID, InitiatorSigningPublicKey: g.SubjectSigningPublicKey, InitiatorReceivingPublicKey: g.SubjectReceivingPublicKey, ApproverDeviceID: eg.Grant.SubjectDeviceID, ApproverSigningPublicKey: eg.Grant.SubjectSigningPublicKey, ApproverReceivingPublicKey: eg.Grant.SubjectReceivingPublicKey}
	a := EnrollmentApproval{Context: context, PairingProfile: EnrollmentPairingProfile, TranscriptHash: strings.Repeat("c", 64), Grants: []SignedGrantWire{GrantToWire(gs)}}
	base, e := a.Certificate()
	recoveryCheck(t, e)
	preHash, e := p.Hash()
	recoveryCheck(t, e)
	cert := EnrollmentCertificateV4{base, preHash}
	a.ApproverSignature, e = SignEnrollmentCertificateV4(cert, parent)
	recoveryCheck(t, e)
	a.InitiatorSignature, e = SignEnrollmentCertificateV4(cert, child)
	recoveryCheck(t, e)
	n := IssuerEnrollment{CertificateVersion: "4", IssuerProofHash: preHash, Approval: a}
	p.Path = append(p.Path, IssuerRecoveryArchive{Kind: "paired", Enrollment: &n})
	fh, e := IssuerAuthorityHash(a.Grants[0])
	recoveryCheck(t, e)
	p.Authorities = append(p.Authorities, IssuerRecoveryAuthority{Grant: a.Grants[0], ParentHash: eh})
	p.Targets = []IssuerTarget{{g.EnvironmentID, fh}}
	v, e = VerifyIssuerRecoveryEvidence(f.RootPin, p)
	recoveryCheck(t, e)
	recoveryCheck(t, v.VerifyTarget(a.Grants[0], g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey))
	b, e := p.CanonicalBytes()
	recoveryCheck(t, e)
	h, e := p.Hash()
	recoveryCheck(t, e)
	cb, e := cert.SigningBytes()
	recoveryCheck(t, e)
	return issuerRecoveryFixture{f, p, hex.EncodeToString(b), h, hex.EncodeToString(cb), strings.Repeat("07", 32)}
}
func TestIssuerRecoveryOriginalRootTransitionDeviceAndPairedChild(t *testing.T) {
	f := makeIssuerRecoveryFixture(t)
	b, e := json.Marshal(f.Proof)
	recoveryCheck(t, e)
	decoded, e := DecodeIssuerRecoveryProof(b)
	recoveryCheck(t, e)
	v, e := VerifyIssuerRecoveryEvidence(f.Recovery.RootPin, decoded)
	recoveryCheck(t, e)
	child := decoded.Path[1].Enrollment.Approval.Grants[0]
	recoveryCheck(t, v.VerifyHistoricalGrant(child))
	if child.Grant.Role != "ro" || decoded.TrustRoot.RootDeviceID != f.Recovery.RootPin.DeviceID || len(v.InitialAuthorities()) != 1 {
		t.Fatal("new device acquired unexpected root or scope")
	}
	bad := child
	bad.Grant.Role = "admin"
	if v.VerifyHistoricalGrant(bad) == nil {
		t.Fatal("selected child RO was raised")
	}
	var fields []any
	canonical, e := decoded.CanonicalBytes()
	recoveryCheck(t, e)
	recoveryCheck(t, json.Unmarshal(canonical, &fields))
	if len(fields) != 12 {
		t.Fatal("wrong v3 canonical field count")
	}
	if os.Getenv("HARMONIA_WRITE_SYNTHETIC_RECOVERY_VECTOR") == "1" {
		b, e := json.MarshalIndent(f, "", "  ")
		recoveryCheck(t, e)
		b = append(b, '\n')
		if strings.Contains(strings.ToLower(string(b)), "sk-") {
			t.Fatal("synthetic vector accidentally matches API prefix; regenerate")
		}
		for _, path := range []string{"testdata/issuer-recovery-v1.json", "../../protocol/vectors/issuer-recovery-v1.json"} {
			recoveryCheck(t, os.WriteFile(path, b, 0644))
		}
	}
}
func TestIssuerRecoveryMissingSubstitutedAndOldSourcesFailClosed(t *testing.T) {
	f := makeIssuerRecoveryFixture(t)
	for _, name := range []string{"missing-transitions", "missing-recovered", "missing-original", "root-replaced", "source-empty", "source-other", "double-source", "recovered-not-first", "unknown-tag", "both-tags", "old-cert-domain", "fake-device-pub", "selected-role", "missing-branch", "same-device-conflict", "null-array"} {
		t.Run(name, func(t *testing.T) {
			p := recoveryClone(t, f.Proof)
			switch name {
			case "missing-transitions":
				p.Transitions = []AcceptedRecoveryTransition{}
			case "missing-recovered":
				p.RecoveredDevices = []AcceptedRecoveredDevice{}
			case "missing-original":
				p.Initialization.DeviceSignature = ""
			case "root-replaced":
				p.TrustRoot.RootDeviceID = "new-root-fake"
			case "source-empty":
				p.Authorities[len(p.Authorities)-2].RecoveryEnrollmentHash = ""
			case "source-other":
				p.Authorities[len(p.Authorities)-2].RecoveryEnrollmentHash = strings.Repeat("f", 64)
			case "double-source":
				p.Authorities[len(p.Authorities)-2].ParentHash = p.Targets[0].AuthorityHash
			case "recovered-not-first":
				p.Path = append(p.Path[1:], p.Path[0])
			case "unknown-tag":
				p.Path[0].Kind = "server-directory"
			case "both-tags":
				p.Path[0].Enrollment = p.Path[1].Enrollment
			case "old-cert-domain":
				p.Path[1].Enrollment.CertificateVersion = "3"
			case "fake-device-pub":
				p.RecoveredDevices[0].Submission.Enrollment.DeviceSigningPublicKey = p.TrustRoot.RootSigningPublicKey
			case "selected-role":
				p.RecoveredDevices[0].Submission.SelectedRights[0].Role = "ro"
			case "missing-branch":
				p.IdentityPaths = [][]IssuerRecoveryArchive{}
			case "same-device-conflict":
				x := recoveryClone(t, p.Path)
				x[1].Enrollment.IssuerProofHash = strings.Repeat("f", 64)
				p.IdentityPaths = append(p.IdentityPaths, x)
			case "null-array":
				p.RecoveredDevices = nil
			}
			if _, e := VerifyIssuerRecoveryEvidence(f.Recovery.RootPin, p); e == nil {
				t.Fatal("unverified recovery graph source accepted")
			}
		})
	}
}

func TestEnrollmentRecoveryV4PAKEAnchorAndStrictReceipt(t *testing.T) {
	f := makeIssuerRecoveryFixture(t)
	p := recoveryClone(t, f.Proof)
	n := *p.Path[1].Enrollment
	p.Path = p.Path[:1]
	p.Authorities = p.Authorities[:len(p.Authorities)-1]
	h, e := IssuerAuthorityHash(p.RecoveredDevices[0].Submission.Grants[0])
	recoveryCheck(t, e)
	p.Targets = []IssuerTarget{{"environment-Y", h}}
	a := EnrollmentApprovalV4{CertificateVersion: "4", Capabilities: []string{RecoveryAuthorityCapability}, Context: n.Approval.Context, PairingProfile: n.Approval.PairingProfile, TranscriptHash: n.Approval.TranscriptHash, Grants: n.Approval.Grants, IssuerProof: p, ApproverSignature: n.Approval.ApproverSignature, InitiatorSignature: n.Approval.InitiatorSignature}
	anchor := ConfirmedEnrollmentAnchor{a.Context, a.TranscriptHash}
	v, e := VerifyCompletedEnrollmentV4(anchor, a)
	recoveryCheck(t, e)
	recoveryCheck(t, v.VerifyHistoricalGrant(a.Grants[0]))
	encoded, e := json.Marshal(a)
	recoveryCheck(t, e)
	_, e = DecodeEnrollmentApprovalV4(encoded)
	recoveryCheck(t, e)
	pending := a
	pending.InitiatorSignature = ""
	_, e = VerifyEnrollmentApprovalV4(anchor, pending)
	recoveryCheck(t, e)
	if _, e = VerifyCompletedEnrollmentV4(anchor, pending); e == nil {
		t.Fatal("pending approval counted as completed")
	}
	for _, name := range []string{"wrong-pake-public", "wrong-transcript", "legacy-profile", "missing-cap", "proof-substitution", "roles-substitution", "missing-old-authority"} {
		t.Run(name, func(t *testing.T) {
			r := recoveryClone(t, a)
			bound := anchor
			switch name {
			case "wrong-pake-public":
				bound.Context.ApproverSigningPublicKey = f.Recovery.RootPin.SigningPublicKey
			case "wrong-transcript":
				bound.TranscriptHash = strings.Repeat("f", 64)
			case "legacy-profile":
				r.CertificateVersion = "3"
			case "missing-cap":
				r.Capabilities = []string{}
			case "proof-substitution":
				r.IssuerProof.TrustRoot.RootDeviceID = "server-root"
			case "roles-substitution":
				r.Grants[0].Grant.Role = "admin"
			case "missing-old-authority":
				r.IssuerProof.Transitions = []AcceptedRecoveryTransition{}
			}
			if _, e := VerifyCompletedEnrollmentV4(bound, r); e == nil {
				t.Fatal("unbound v4 approval receipt accepted")
			}
		})
	}
	for name, b := range map[string][]byte{
		"duplicate-top":             append([]byte(`{"certificateVersion":"4",`), encoded[1:]...),
		"duplicate-nested":          bytes.Replace(encoded, []byte(`"kind":"recovered"`), []byte(`"kind":"recovered","kind":"paired"`), 1),
		"null-required":             bytes.Replace(encoded, []byte(`"capabilities":["issuer-recovery-v1"]`), []byte(`"capabilities":null`), 1),
		"missing-empty-right-field": bytes.Replace(encoded, []byte(`,"recoveryEnrollmentHash":""`), nil, 1),
		"unknown-tag-field":         bytes.Replace(encoded, []byte(`"kind":"recovered"`), []byte(`"kind":"recovered","forbiddenDirectory":true`), 1),
		"trailing":                  append(append([]byte(nil), encoded...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeEnrollmentApprovalV4(b); e == nil {
				t.Fatal("ambiguous v4 receipt schema accepted")
			}
		})
	}
}
func TestRecoveryAuthorityStaticVectors(t *testing.T) {
	data, e := os.ReadFile("testdata/recovery-authority-v1.json")
	recoveryCheck(t, e)
	var f recoveryAuthorityFixture
	recoveryCheck(t, json.Unmarshal(data, &f))
	v, e := VerifyRecoveryInitialization(f.RootPin, f.Original)
	recoveryCheck(t, e)
	for _, r := range []AcceptedRecoveryTransition{f.OldCode, f.AllAdmin, f.Reanchor} {
		_, e := VerifyAcceptedRecoveryTransition(v, r)
		recoveryCheck(t, e)
	}
	advance, e := VerifyAcceptedRecoveryTransition(v, f.OldCode)
	recoveryCheck(t, e)
	_, e = VerifyAcceptedRecoveredDevice(advance, f.Device)
	recoveryCheck(t, e)
	h, e := f.Original.Hash()
	recoveryCheck(t, e)
	if h != f.InitializationHash {
		t.Fatal("static initialization ref mismatch")
	}
	for _, row := range []struct {
		r         AcceptedRecoveryTransition
		hex, hash string
	}{{f.OldCode, f.TransitionSigningHex, f.TransitionHash}, {f.AllAdmin, f.AdminSigningHex, f.AdminHash}, {f.Reanchor, f.ReanchorSigningHex, f.ReanchorHash}} {
		b, e := row.r.Submission.Transition.SigningBytes()
		recoveryCheck(t, e)
		h, e := RecoveryTransitionHash(row.r.Submission)
		recoveryCheck(t, e)
		if hex.EncodeToString(b) != row.hex || h != row.hash {
			t.Fatal("static transition canonical mismatch")
		}
	}
	data, e = os.ReadFile("testdata/issuer-recovery-v1.json")
	recoveryCheck(t, e)
	var graph issuerRecoveryFixture
	recoveryCheck(t, json.Unmarshal(data, &graph))
	_, e = VerifyIssuerRecoveryEvidence(graph.Recovery.RootPin, graph.Proof)
	recoveryCheck(t, e)
	b, e := graph.Proof.CanonicalBytes()
	recoveryCheck(t, e)
	h, e = graph.Proof.Hash()
	recoveryCheck(t, e)
	if hex.EncodeToString(b) != graph.CanonicalHex || h != graph.Hash {
		t.Fatal("static graph canonical mismatch")
	}
}
