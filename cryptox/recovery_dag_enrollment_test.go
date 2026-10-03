package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func makeDAGApproval(t *testing.T, p IssuerRecoveryDAG) EnrollmentApprovalV5 {
	t.Helper()
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	child := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, 32))
	x, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{20}, 32))
	recoveryCheck(t, e)
	c := EnrollmentContext{Purpose: "enroll-device", AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, SessionID: "second-recovered-G-pairs-H", ChallengeNonce: EncodeBase64(bytes.Repeat([]byte{82}, 32)), ExpiresAt: "2030000100", InitiatorDeviceID: "paired-H-after-second-recovery", InitiatorSigningPublicKey: EncodeBase64(child.Public().(ed25519.PublicKey)), InitiatorReceivingPublicKey: EncodeBase64(x.PublicKey().Bytes()), ApproverDeviceID: "recovered-G", ApproverSigningPublicKey: EncodeBase64(manager.Public().(ed25519.PublicKey)), ApproverReceivingPublicKey: p.Records[3].RecoveredV2.Submission.Enrollment.DeviceReceivingPublicKey}
	a := EnrollmentApprovalV5{CertificateVersion: "5", Capabilities: []string{RecoveryDAGCapability}, Context: c, PairingProfile: EnrollmentPairingProfile, TranscriptHash: strings.Repeat("e", 64), Grants: []SignedGrantWire{}, IssuerProof: p}
	for _, parent := range p.Records[3].RecoveredV2.Submission.Grants {
		g := parent.Grant
		g.IssuerDeviceID = c.ApproverDeviceID
		g.SubjectDeviceID = c.InitiatorDeviceID
		g.SubjectSigningPublicKey = c.InitiatorSigningPublicKey
		g.SubjectReceivingPublicKey = c.InitiatorReceivingPublicKey
		g.Role = "ro"
		g.IdempotencyKey = "G-approves-H-" + g.EnvironmentID
		key := bytes.Repeat([]byte{9}, 32)
		if g.EnvironmentID == "environment-Z" {
			key = bytes.Repeat([]byte{21}, 32)
		}
		packet, e := WrapEnvironmentKey(key, EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey})
		recoveryCheck(t, e)
		g.Envelope = EncodeBase64(packet)
		signed, e := SignGrant(g, manager)
		recoveryCheck(t, e)
		a.Grants = append(a.Grants, GrantToWire(signed))
	}
	cert, e := a.Certificate()
	recoveryCheck(t, e)
	a.ApproverSignature, e = SignEnrollmentCertificateV5(cert, manager)
	recoveryCheck(t, e)
	a.InitiatorSignature, e = SignEnrollmentCertificateV5(cert, child)
	recoveryCheck(t, e)
	return a
}
func TestRecoveryDAGRecoveredManagerApprovesNewDeviceBoundToConfirmedAnchor(t *testing.T) {
	f := makeRecoveryDAGFixture(t)
	a := f.Approval
	anchor := ConfirmedEnrollmentAnchor{a.Context, a.TranscriptHash}
	b, e := json.Marshal(a)
	recoveryCheck(t, e)
	decoded, e := DecodeEnrollmentApprovalV5(b)
	recoveryCheck(t, e)
	if _, e = VerifyCompletedEnrollmentV5(anchor, decoded); e != nil {
		t.Fatal("confirmed second recovery manager approval rejected", e)
	}
	// 把证书与 RO 权源真正归档至普通图；这不模拟线上 device/current 权限检查。
	p := recoveryClone(t, f.Proof)
	n := IssuerEnrollment{CertificateVersion: "5", IssuerProofHash: f.Hash, Approval: EnrollmentApproval{a.Context, a.PairingProfile, a.TranscriptHash, a.Grants, a.ApproverSignature, a.InitiatorSignature}}
	p.Source.View.Path = append(p.Source.View.Path, IssuerRecoveryArchive{Kind: "paired", Enrollment: &n})
	p.Source.View.Targets = []IssuerTarget{}
	for _, g := range a.Grants {
		for _, parent := range f.Proof.Records[3].RecoveredV2.Submission.Grants {
			if parent.Grant.EnvironmentID == g.Grant.EnvironmentID {
				h, e := IssuerAuthorityHash(parent)
				recoveryCheck(t, e)
				p.Source.View.Authorities = append(p.Source.View.Authorities, IssuerRecoveryAuthority{Grant: g, ParentHash: h})
			}
		}
		h, e := IssuerAuthorityHash(g)
		recoveryCheck(t, e)
		p.Source.View.Targets = append(p.Source.View.Targets, IssuerTarget{g.Grant.EnvironmentID, h})
	}
	v, e := VerifyIssuerRecoveryDAG(f.RootPin, p)
	recoveryCheck(t, e)
	for _, g := range a.Grants {
		recoveryCheck(t, v.VerifyTarget(g, a.Context.InitiatorDeviceID, a.Context.InitiatorSigningPublicKey, a.Context.InitiatorReceivingPublicKey))
	}
	for _, name := range []string{"manager-X", "transcript", "missing-initiator-signature", "old-cert-domain", "changed-role", "root-as-manager", "capability", "retired-recovery-as-device"} {
		t.Run(name, func(t *testing.T) {
			x := recoveryClone(t, a)
			an := anchor
			switch name {
			case "manager-X":
				an.Context.ApproverReceivingPublicKey = an.Context.InitiatorReceivingPublicKey
			case "transcript":
				an.TranscriptHash = strings.Repeat("f", 64)
			case "missing-initiator-signature":
				x.InitiatorSignature = ""
			case "old-cert-domain":
				x.CertificateVersion = "4"
			case "changed-role":
				x.Grants[0].Grant.Role = "admin"
			case "root-as-manager":
				an.Context.ApproverDeviceID = f.RootPin.DeviceID
			case "capability":
				x.Capabilities = []string{RecoveryAuthorityCapability}
			case "retired-recovery-as-device":
				x.Context.InitiatorSigningPublicKey = f.Proof.Records[0].TransitionV1.Submission.Transition.OldRecoverySigningPublicKey
			}
			if _, e := VerifyCompletedEnrollmentV5(an, x); e == nil {
				t.Fatal("changed confirmed enrollment accepted")
			}
		})
	}
}
func TestRecoveryDAGPrivateContextIsolationAndConcurrentTypedSigning(t *testing.T) {
	f := makeRecoveryDAGFixture(t)
	b := RecoveryDependencyBundle{f.Proof.Initialization, f.Proof.Records[:4]}
	d, e := VerifyRecoveryDependencyBundle(f.RootPin, b)
	recoveryCheck(t, e)
	s := recoveryClone(t, f.Proof.Records[4].TransitionV2.Submission)
	b.Records[3].RecoveredV2.Submission.Grants[0].Grant.Role = "ro"
	b.Initialization.Proposal.Device.ID = "changed-caller-state"
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := SignAllAdminRecoveryTransitionV2(d, s, key, time.Unix(f.SyntheticNow, 0))
			errors <- err
		})
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal("caller mutation changed trusted context", err)
		}
	}
	// 解码命令保持 new profile 的 exact wrapper；不从裸 JSON 自动加载私钥或发请求。
	command := RecoveryTransitionCommandV2{s, RecoveryDependencyBundle{f.Proof.Initialization, f.Proof.Records[:4]}}
	raw, e := json.Marshal(command)
	recoveryCheck(t, e)
	// f 被上面的别名写入有意破坏；可信检查仍须 pin。
	if _, e = DecodeRecoveryTransitionCommandV2(raw); e != nil {
		t.Fatal("well-shaped modified command failed syntax-only decode", e)
	}
	if _, e = VerifyRecoveryDependencyBundle(f.RootPin, command.DependencyBundle); e == nil {
		t.Fatal("changed dependency bundle became trusted")
	}
}

func TestRecoveryDAGValidUnusedAcceptedDeviceCannotExpandClosure(t *testing.T) {
	f := makeRecoveryDAGFixture(t)
	d, e := VerifyIssuerRecoveryDAG(f.RootPin, f.Proof)
	recoveryCheck(t, e)
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, 32))
	rec, e := DeriveRecoveryKeys(bytes.Repeat([]byte{70}, 32), f.RootPin.AccountID, "1", "4")
	recoveryCheck(t, e)
	defer clear(rec.SigningPrivate)
	defer clear(rec.ReceivingPrivate)
	s := recoveryClone(t, f.Proof.Records[3].RecoveredV2.Submission)
	s.Enrollment.RecoveryGeneration = "4"
	s.Enrollment.RecoveryTransitionHash = d.current.head
	s.Enrollment.OperationID = "otherwise-valid-unused-H"
	s.Enrollment.ChallengeID = "unused-H-challenge"
	s.Enrollment.ExpectedSequence = "42"
	s.Enrollment.DeviceID = f.Approval.Context.InitiatorDeviceID
	s.Enrollment.DeviceSigningPublicKey = f.Approval.Context.InitiatorSigningPublicKey
	s.Enrollment.DeviceReceivingPublicKey = f.Approval.Context.InitiatorReceivingPublicKey
	s.IssuerEvidence = recoveryClone(t, f.Proof.Source)
	s.Grants = []SignedGrantWire{}
	s.SelectedRights = []RecoveredDeviceRight{}
	s.Envelopes = []RecoveryEnvelope{}
	for _, packet := range f.Approval.Grants {
		g := packet.Grant
		g.IssuerDeviceID = s.Enrollment.DeviceID
		g.IdempotencyKey = "unused-H-self-" + g.EnvironmentID
		sg, e := SignGrant(g, k)
		recoveryCheck(t, e)
		s.Grants = append(s.Grants, GrantToWire(sg))
		s.SelectedRights = append(s.SelectedRights, RecoveredDeviceRight{g.EnvironmentID, g.KeyVersion, g.Role, g.ExpiresAt})
		s.Envelopes = append(s.Envelopes, RecoveryEnvelope{g.EnvironmentID, g.KeyVersion, g.Envelope})
	}
	s.Enrollment.SelectedRightsHash, e = RecoveredDeviceRightsHash(s.SelectedRights)
	recoveryCheck(t, e)
	s.Enrollment.GrantsHash, e = RecoveredDeviceGrantsHash(s.Grants)
	recoveryCheck(t, e)
	s.Enrollment.EnvelopesHash, e = RecoveredDeviceEnvelopesHash(s.Envelopes)
	recoveryCheck(t, e)
	s.Enrollment.IssuerEvidenceHash, e = s.IssuerEvidence.Hash()
	recoveryCheck(t, e)
	s.RecoverySignature, e = SignRecoveredDeviceByRecoveryV2(d, s, rec.SigningPrivate, time.Unix(f.SyntheticNow, 0))
	recoveryCheck(t, e)
	s.DeviceSignature, e = SignRecoveredDeviceAfterHPKEV2(d, s, k, bytes.Repeat([]byte{20}, 32), time.Unix(f.SyntheticNow, 0))
	recoveryCheck(t, e)
	record := AcceptedRecoveredDeviceV2{s, 43}
	p := recoveryClone(t, f.Proof)
	p.Records = append(p.Records, RecoveryDAGRecord{Kind: "recovered-v2", RecoveredV2: &record})
	if _, e = VerifyRecoveryDependencyBundle(f.RootPin, RecoveryDependencyBundle{p.Initialization, p.Records}); e != nil {
		t.Fatal("otherwise valid unused device failed independently", e)
	}
	if _, e = VerifyIssuerRecoveryDAG(f.RootPin, p); e == nil {
		t.Fatal("unreferenced accepted device expanded source closure")
	}
}

func TestRecoveryDAGOuterSourceDoesNotRetainCallerOrigins(t *testing.T) {
	f := makeRecoveryDAGFixture(t)
	p := recoveryClone(t, f.Proof)
	v, e := VerifyIssuerRecoveryDAG(f.RootPin, p)
	recoveryCheck(t, e)
	original := recoveryClone(t, f.Creation.Origin)
	authority := p.Records[3].RecoveredV2.Submission.IssuerEvidence.View.Authorities
	var parent SignedGrantWire
	for _, a := range authority {
		if a.Grant.Grant.SubjectDeviceID == "recovered-E" && a.Grant.Grant.EnvironmentID == "environment-Y" {
			parent = a.Grant
		}
	}
	recoveryCheck(t, v.VerifyEnvironmentOriginEvent(SignedEnvironmentChange{f.Creation.Change, f.Creation.Signature}, original, parent))
	for i := range p.Source.View.Origins {
		if p.Source.View.Origins[i].Origin.EnvironmentID == "environment-Z" {
			p.Source.View.Origins[i].Origin.After[0].Role = "ro"
		}
	}
	p.Source.View.Authorities[0].Grant.Grant.Role = "ro"
	p.Records[4].TransitionV2.Submission.Transition.NewRecoveryGeneration = "9"
	recoveryCheck(t, v.VerifyEnvironmentOriginEvent(SignedEnvironmentChange{f.Creation.Change, f.Creation.Signature}, original, parent))
	point, e := v.RecoveryCheckpoint()
	recoveryCheck(t, e)
	if point.RecoveryGeneration != "4" {
		t.Fatal("caller mutation changed already verified head")
	}
}

func TestRecoveryDAGStrictCommandsAndCommittedGoldenFixture(t *testing.T) {
	raw, e := os.ReadFile("testdata/recovery-dag-v1.json")
	recoveryCheck(t, e)
	var f recoveryDAGFixture
	recoveryCheck(t, json.Unmarshal(raw, &f))
	v, e := VerifyIssuerRecoveryDAG(f.RootPin, f.Proof)
	recoveryCheck(t, e)
	cb, e := f.Proof.CanonicalBytes()
	recoveryCheck(t, e)
	if hex.EncodeToString(cb) != f.CanonicalHex {
		t.Fatal("committed golden bytes changed")
	}
	h, e := f.Proof.Hash()
	recoveryCheck(t, e)
	if h != f.Hash {
		t.Fatal("committed golden hash changed")
	}
	recoveryCheck(t, v.VerifyHistoricalMutationSource(f.Cipher, findDAGGrant(f.Proof, "recovered-E", "environment-Z")))
	transition := RecoveryTransitionCommandV2{f.Proof.Records[4].TransitionV2.Submission, RecoveryDependencyBundle{f.Proof.Initialization, f.Proof.Records[:4]}}
	r, e := json.Marshal(transition)
	recoveryCheck(t, e)
	if _, e = DecodeRecoveryTransitionCommandV2(r); e != nil {
		t.Fatal("valid new transition command rejected", e)
	}
	device := RecoveredDeviceCommandV2{f.Proof.Records[3].RecoveredV2.Submission, RecoveryDependencyBundle{f.Proof.Initialization, f.Proof.Records[:3]}}
	r, e = json.Marshal(device)
	recoveryCheck(t, e)
	if _, e = DecodeRecoveredDeviceCommandV2(r); e != nil {
		t.Fatal("valid new recovered command rejected", e)
	}
	for _, name := range []string{"bundle-null", "source-null", "duplicate", "unknown", "trailing"} {
		t.Run(name, func(t *testing.T) {
			m := map[string]json.RawMessage{}
			recoveryCheck(t, json.Unmarshal(r, &m))
			var malformed []byte
			switch name {
			case "bundle-null":
				m["dependencyBundle"] = json.RawMessage("null")
				malformed, _ = json.Marshal(m)
			case "source-null":
				var sub map[string]json.RawMessage
				recoveryCheck(t, json.Unmarshal(m["submission"], &sub))
				sub["issuerEvidence"] = json.RawMessage("null")
				m["submission"], _ = json.Marshal(sub)
				malformed, _ = json.Marshal(m)
			case "duplicate":
				malformed = append([]byte(`{"dependencyBundle":{},`), r[1:]...)
			case "unknown":
				malformed = append([]byte(`{"unknown":false,`), r[1:]...)
			case "trailing":
				malformed = append(bytes.Clone(r), []byte(` {}`)...)
			}
			if _, e := DecodeRecoveredDeviceCommandV2(malformed); e == nil {
				t.Fatal("invalid new command accepted")
			}
		})
	}
	// v2 old-code 标量和旧 v1 DTO 同形；旧域验签必须拒绝，绝不因 decode 成功降级。
	prior, e := VerifyRecoveryInitialization(f.RootPin, f.Proof.Initialization)
	recoveryCheck(t, e)
	prior, e = VerifyAcceptedRecoveryTransition(prior, *f.Proof.Records[0].TransitionV1)
	recoveryCheck(t, e)
	s := f.Proof.Records[2].TransitionV2.Submission
	old := RecoveryTransitionSubmission{RecoveryAuthorityTransition(s.Transition), s.EnvironmentManifest, s.AuthoritySet, nil, s.Envelopes, s.NewTrustRoot, s.LegacyState, s.AuthorizationSignature, s.NewRecoverySignature}
	if _, e = VerifyAcceptedRecoveryTransition(prior, AcceptedRecoveryTransition{old, 40}); e == nil {
		t.Fatal("v2 signature accepted under old transition domain")
	}
}
func findDAGGrant(p IssuerRecoveryDAG, subject, env string) SignedGrantWire {
	for _, a := range p.Source.View.Authorities {
		if a.Grant.Grant.SubjectDeviceID == subject && a.Grant.Grant.EnvironmentID == env {
			return a.Grant
		}
	}
	return SignedGrantWire{}
}
