package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// Fixtures use actual initialization signatures and certificate-5 approvals.
// Each archive commits the issuer DAG that existed before that approval.
func newIssuerDAGFixture(t *testing.T) issuerProofVector {
	t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	recv := map[string][]byte{}
	seeds, receiving := map[string]string{}, map[string]string{}
	for i, name := range []string{"A", "B", "C"} {
		seed := bytes.Repeat([]byte{byte(i + 1)}, 32)
		keys[name] = ed25519.NewKeyFromSeed(seed)
		x, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{byte(i + 11)}, 32))
		recoveryCheck(t, e)
		recv[name] = x.PublicKey().Bytes()
		seeds[name], receiving[name] = hex.EncodeToString(seed), hex.EncodeToString(x.Bytes())
	}
	rec, e := DeriveRecoveryKeys(bytes.Repeat([]byte{66}, 32), "account-fixture", "1", "1")
	recoveryCheck(t, e)
	root, e := SignTrustRoot("account-fixture", "1", TrustRoot{RootDeviceID: "device-A", RootSigningPublicKey: EncodeBase64(keys["A"].Public().(ed25519.PublicKey)), RootReceivingPublicKey: EncodeBase64(recv["A"]), RecoveryGeneration: "1", RecoverySigningPublicKey: EncodeBase64(rec.SigningPublic), RecoveryReceivingPublicKey: EncodeBase64(rec.ReceivingPublic)}, rec.SigningPrivate)
	recoveryCheck(t, e)
	makeGrant := func(subject, issuer, role string) SignedGrantWire {
		g := Grant{AccountID: "account-fixture", AccountGeneration: "1", EnvironmentID: "env-fixture", KeyVersion: "1", GrantGeneration: "1", IssuerDeviceID: "device-" + issuer, SubjectDeviceID: "device-" + subject, SubjectSigningPublicKey: EncodeBase64(keys[subject].Public().(ed25519.PublicKey)), SubjectReceivingPublicKey: EncodeBase64(recv[subject]), Role: role, ExpiresAt: "0", IdempotencyKey: "initial-" + subject}
		packet, e := WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), EnvelopeContext{g.AccountID, "1", g.EnvironmentID, "1", "device", g.SubjectDeviceID, "1", g.SubjectReceivingPublicKey})
		recoveryCheck(t, e)
		g.Envelope = EncodeBase64(packet)
		if subject == "C" {
			g.ExpiresAt = "2030000300"
		}
		signed, e := SignGrant(g, keys[issuer])
		recoveryCheck(t, e)
		return GrantToWire(signed)
	}
	ga, gb, gc := makeGrant("A", "A", "admin"), makeGrant("B", "A", "admin"), makeGrant("C", "B", "ro")
	packet, e := WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), EnvelopeContext{"account-fixture", "1", "env-fixture", "1", "recovery", "account-fixture", "1", root.RecoveryReceivingPublicKey})
	recoveryCheck(t, e)
	proposal := InitializationProposal{IdempotencyKey: "original-init", Device: InitializationDevice{ID: root.RootDeviceID, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey}, RecoveryGeneration: "1", RecoverySigningPublicKey: root.RecoverySigningPublicKey, RecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, TrustRootSignature: root.Signature, Environments: []InitializationEnvironment{{EnvironmentID: "env-fixture", KeyVersion: "1", RecoveryEnvelope: EncodeBase64(packet), Grant: ga}}}
	ph, e := proposal.Hash("account-fixture", "1")
	recoveryCheck(t, e)
	proof, e := NewInitializationProof("account-fixture", "1", "synthetic-init-bearer", "init-challenge", EncodeBase64(bytes.Repeat([]byte{70}, 32)), "2030000100", ph)
	recoveryCheck(t, e)
	ds, e := SignInitializationProof(proof, keys["A"])
	recoveryCheck(t, e)
	rs, e := SignInitializationProof(proof, rec.SigningPrivate)
	recoveryCheck(t, e)
	original := OriginalInitialization{Proposal: proposal, Proof: proof, DeviceSignature: ds, RecoverySignature: rs, Sequence: 1}
	ih, e := original.Hash()
	recoveryCheck(t, e)
	ha, e := IssuerAuthorityHash(ga)
	recoveryCheck(t, e)
	hb, e := IssuerAuthorityHash(gb)
	recoveryCheck(t, e)
	p := IssuerRecoveryDAG{Profile: IssuerRecoveryDAGProfile, AccountID: "account-fixture", AccountGeneration: "1", Initialization: original, Records: []RecoveryDAGRecord{}, Source: RecoverySource{Kind: "proof3", View: &RecoverySourceView{Profile: RecoverySourceViewProfile, AccountID: "account-fixture", AccountGeneration: "1", InitializationHash: ih, TrustRoot: root, RecoveryHeadHash: ih, Path: []IssuerRecoveryArchive{}, Authorities: []IssuerRecoveryAuthority{{Grant: ga}}, Targets: []IssuerTarget{{"env-fixture", ha}}, Origins: []SignedEnvironmentOrigin{}, IdentityPaths: [][]IssuerRecoveryArchive{}, Dependencies: []RecoveryDependency{}}}}
	makeApproval := func(parent, child string, g SignedGrantWire, p IssuerRecoveryDAG) EnrollmentApprovalV5 {
		c := EnrollmentContext{Purpose: "enroll-device", AccountID: "account-fixture", AccountGeneration: "1", SessionID: "pairing-" + child, ChallengeNonce: EncodeBase64(bytes.Repeat([]byte{42}, 32)), ExpiresAt: "2030000100", InitiatorDeviceID: g.Grant.SubjectDeviceID, InitiatorSigningPublicKey: g.Grant.SubjectSigningPublicKey, InitiatorReceivingPublicKey: g.Grant.SubjectReceivingPublicKey, ApproverDeviceID: "device-" + parent, ApproverSigningPublicKey: EncodeBase64(keys[parent].Public().(ed25519.PublicKey)), ApproverReceivingPublicKey: EncodeBase64(recv[parent])}
		a := EnrollmentApprovalV5{CertificateVersion: "5", Capabilities: []string{RecoveryDAGCapability}, Context: c, PairingProfile: EnrollmentPairingProfile, TranscriptHash: strings.Repeat("a", 64), Grants: []SignedGrantWire{g}, IssuerProof: recoveryClone(t, p)}
		cert, e := a.Certificate()
		recoveryCheck(t, e)
		a.ApproverSignature, e = SignEnrollmentCertificateV5(cert, keys[parent])
		recoveryCheck(t, e)
		a.InitiatorSignature, e = SignEnrollmentCertificateV5(cert, keys[child])
		recoveryCheck(t, e)
		_, e = VerifyCompletedEnrollmentV5(ConfirmedEnrollmentAnchor{c, a.TranscriptHash}, a)
		recoveryCheck(t, e)
		return a
	}
	a := makeApproval("A", "B", gb, p)
	cert, e := a.Certificate()
	recoveryCheck(t, e)
	p.Source.View.Path = []IssuerRecoveryArchive{{Kind: "paired", Enrollment: &IssuerEnrollment{CertificateVersion: "5", IssuerProofHash: cert.IssuerProofHash, Approval: EnrollmentApproval{a.Context, a.PairingProfile, a.TranscriptHash, a.Grants, a.ApproverSignature, a.InitiatorSignature}}}}
	p.Source.View.Authorities = append(p.Source.View.Authorities, IssuerRecoveryAuthority{Grant: gb, ParentHash: ha})
	p.Source.View.Targets = []IssuerTarget{{"env-fixture", hb}}
	a = makeApproval("B", "C", gc, p)
	cipher, e := EncryptValue(bytes.Repeat([]byte{9}, 32), ValueContext{"account-fixture", "1", "env-fixture", "1", "SYNTHETIC_VALUE"}, []byte("synthetic-only"))
	recoveryCheck(t, e)
	mutation, e := SignMutation(Mutation{AccountID: "account-fixture", AccountGeneration: "1", DeviceID: "device-A", EnvironmentID: "env-fixture", KeyVersion: "1", GrantGeneration: "1", Operation: "put", IdempotencyKey: "root-write", Name: "SYNTHETIC_VALUE", Payload: EncodeBase64(cipher)}, keys["A"])
	recoveryCheck(t, e)
	canonical, e := p.CanonicalBytes()
	recoveryCheck(t, e)
	h, e := p.Hash()
	recoveryCheck(t, e)
	cert, e = a.Certificate()
	recoveryCheck(t, e)
	cb, e := cert.SigningBytes()
	recoveryCheck(t, e)
	return issuerProofVector{Now: 2030000000, SigningSeeds: seeds, ReceivingKeys: receiving, EnvironmentKey: strings.Repeat("09", 32), Approval: a, ProofCanonicalHex: hex.EncodeToString(canonical), ProofHash: h, CertificateSigningHex: hex.EncodeToString(cb), AuthorityHashes: map[string]string{"A": ha, "B": hb}, HistoricalMutation: mutation, HistoricalAuthorization: ga}
}
