// Package dagfixture builds public, signed inputs for cross-package tests.
package dagfixture

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
)

func check(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func Clone[T any](t testing.TB, value T) T {
	t.Helper()
	raw, e := json.Marshal(value)
	check(t, e)
	var out T
	check(t, json.Unmarshal(raw, &out))
	return out
}

func Root(t testing.TB, account string, root cryptox.TrustRoot, signing, recovery ed25519.PrivateKey, environments []cryptox.InitializationEnvironment) cryptox.IssuerRecoveryDAG {
	t.Helper()
	proposal := cryptox.InitializationProposal{IdempotencyKey: "fixture-initialization", Device: cryptox.InitializationDevice{ID: root.RootDeviceID, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey}, RecoveryGeneration: "1", RecoverySigningPublicKey: root.RecoverySigningPublicKey, RecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, TrustRootSignature: root.Signature, Environments: environments}
	ph, e := proposal.Hash(account, "1")
	check(t, e)
	proof, e := cryptox.NewInitializationProof(account, "1", "synthetic-fixture-token", "fixture-init-challenge", cryptox.EncodeBase64(bytes.Repeat([]byte{70}, 32)), "4102444800", ph)
	check(t, e)
	ds, e := cryptox.SignInitializationProof(proof, signing)
	check(t, e)
	rs, e := cryptox.SignInitializationProof(proof, recovery)
	check(t, e)
	original := cryptox.OriginalInitialization{Proposal: proposal, Proof: proof, DeviceSignature: ds, RecoverySignature: rs, Sequence: 1}
	ih, e := original.Hash()
	check(t, e)
	source := cryptox.RecoverySourceView{Profile: cryptox.RecoverySourceViewProfile, AccountID: account, AccountGeneration: "1", InitializationHash: ih, RecoveryHeadHash: ih, TrustRoot: root, Path: []cryptox.IssuerRecoveryArchive{}, Authorities: []cryptox.IssuerRecoveryAuthority{}, Targets: []cryptox.IssuerTarget{}, Origins: []cryptox.SignedEnvironmentOrigin{}, IdentityPaths: [][]cryptox.IssuerRecoveryArchive{}, Dependencies: []cryptox.RecoveryDependency{}}
	for _, env := range environments {
		h, e := cryptox.IssuerAuthorityHash(env.Grant)
		check(t, e)
		source.Authorities = append(source.Authorities, cryptox.IssuerRecoveryAuthority{Grant: env.Grant})
		source.Targets = append(source.Targets, cryptox.IssuerTarget{EnvironmentID: env.EnvironmentID, AuthorityHash: h})
	}
	p := cryptox.IssuerRecoveryDAG{Profile: cryptox.IssuerRecoveryDAGProfile, AccountID: account, AccountGeneration: "1", Initialization: original, Source: cryptox.RecoverySource{Kind: "proof3", View: &source}, Records: []cryptox.RecoveryDAGRecord{}}
	_, e = cryptox.VerifyIssuerRecoveryDAG(cryptox.PinnedIssuerRoot{AccountID: account, AccountGeneration: "1", DeviceID: root.RootDeviceID, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey}, p)
	check(t, e)
	return p
}

func Enroll(t testing.TB, p cryptox.IssuerRecoveryDAG, context cryptox.EnrollmentContext, grants []cryptox.SignedGrantWire, parent, child ed25519.PrivateKey) (cryptox.EnrollmentApprovalV5, cryptox.IssuerRecoveryDAG) {
	t.Helper()
	a := cryptox.EnrollmentApprovalV5{CertificateVersion: "5", Capabilities: []string{cryptox.RecoveryDAGCapability}, Context: context, PairingProfile: cryptox.EnrollmentPairingProfile, TranscriptHash: strings.Repeat("a", 64), Grants: grants, IssuerProof: Clone(t, p)}
	cert, e := a.Certificate()
	check(t, e)
	a.ApproverSignature, e = cryptox.SignEnrollmentCertificateV5(cert, parent)
	check(t, e)
	a.InitiatorSignature, e = cryptox.SignEnrollmentCertificateV5(cert, child)
	check(t, e)
	_, e = cryptox.VerifyCompletedEnrollmentV5(cryptox.ConfirmedEnrollmentAnchor{Context: context, TranscriptHash: a.TranscriptHash}, a)
	check(t, e)
	p = Clone(t, p)
	view := p.Source.View
	view.Path = append(view.Path, cryptox.IssuerRecoveryArchive{Kind: "paired", Enrollment: &cryptox.IssuerEnrollment{CertificateVersion: "5", IssuerProofHash: cert.IssuerProofHash, Approval: cryptox.EnrollmentApproval{Context: context, PairingProfile: a.PairingProfile, TranscriptHash: a.TranscriptHash, Grants: grants, ApproverSignature: a.ApproverSignature, InitiatorSignature: a.InitiatorSignature}}})
	parents := map[string]string{}
	for _, target := range view.Targets {
		parents[target.EnvironmentID] = target.AuthorityHash
	}
	view.Targets = []cryptox.IssuerTarget{}
	for _, g := range grants {
		h, e := cryptox.IssuerAuthorityHash(g)
		check(t, e)
		view.Authorities = append(view.Authorities, cryptox.IssuerRecoveryAuthority{Grant: g, ParentHash: parents[g.Grant.EnvironmentID]})
		view.Targets = append(view.Targets, cryptox.IssuerTarget{EnvironmentID: g.Grant.EnvironmentID, AuthorityHash: h})
	}
	return a, p
}
