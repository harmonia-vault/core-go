package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"strings"
	"testing"
)

type issuerRecoveryFixture struct {
	Recovery recoveryAuthorityFixture
	Proof    IssuerRecoveryDAG
}

func makeIssuerRecoveryFixture(t *testing.T) issuerRecoveryFixture {
	t.Helper()
	f := makeRecoveryAuthorityFixture(t)
	s := f.Device.Submission
	p := recoveryClone(t, f.Proof)
	er, e := RecoveredDeviceReferenceHashV2(s)
	recoveryCheck(t, e)
	if len(p.Source.View.Path) > 0 {
		p.Source.View.IdentityPaths = append(p.Source.View.IdentityPaths, p.Source.View.Path)
	}
	p.Source.View.Path = []IssuerRecoveryArchive{{Kind: "recovered", RecoveryEnrollmentHash: er}}
	eg := s.Grants[0]
	eh, e := IssuerAuthorityHash(eg)
	recoveryCheck(t, e)
	p.Source.View.Authorities = append(p.Source.View.Authorities, IssuerRecoveryAuthority{Grant: eg, RecoveryEnrollmentHash: er})
	p.Source.View.Targets = []IssuerTarget{{eg.Grant.EnvironmentID, eh}}
	dagBindDependencies(t, &p.Source, RecoveryDependencyBundle{p.Initialization, p.Records})
	v, e := VerifyIssuerRecoveryDAG(f.RootPin, p)
	recoveryCheck(t, e)
	// 这里只验证真实 Ed/HPKE 与历史证明。PAKE transport 的运行另由端到端验收负责。
	parent := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
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
	cert := EnrollmentCertificateV5{base, preHash}
	a.ApproverSignature, e = SignEnrollmentCertificateV5(cert, parent)
	recoveryCheck(t, e)
	a.InitiatorSignature, e = SignEnrollmentCertificateV5(cert, child)
	recoveryCheck(t, e)
	n := IssuerEnrollment{CertificateVersion: "5", IssuerProofHash: preHash, Approval: a}
	p.Source.View.Path = append(p.Source.View.Path, IssuerRecoveryArchive{Kind: "paired", Enrollment: &n})
	fh, e := IssuerAuthorityHash(a.Grants[0])
	recoveryCheck(t, e)
	p.Source.View.Authorities = append(p.Source.View.Authorities, IssuerRecoveryAuthority{Grant: a.Grants[0], ParentHash: eh})
	p.Source.View.Targets = []IssuerTarget{{g.EnvironmentID, fh}}
	v, e = VerifyIssuerRecoveryDAG(f.RootPin, p)
	recoveryCheck(t, e)
	recoveryCheck(t, v.VerifyTarget(a.Grants[0], g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey))
	return issuerRecoveryFixture{f, p}
}
