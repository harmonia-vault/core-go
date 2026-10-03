package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 静态向量仅检验受保护证书/本机绑定，真实PAKE/daemon另由联合验收执行。
func TestProtectedCert4StoredOriginalReceiptExactIdentity(t *testing.T) {
	var f struct {
		Proof    cryptox.IssuerRecoveryProof `json:"proof"`
		Seed     string                      `json:"syntheticChildEdSeedHex"`
		Recovery struct {
			Accepted cryptox.AcceptedRecoveredDevice `json:"recoveredDevice"`
		} `json:"recovery"`
	}
	data, e := os.ReadFile("../../cryptox/testdata/issuer-recovery-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &f); e != nil {
		t.Fatal(e)
	}
	n := f.Proof.Path[len(f.Proof.Path)-1].Enrollment
	a := n.Approval
	p := f.Proof
	p.Path = p.Path[:len(p.Path)-1]
	p.Targets = []cryptox.IssuerTarget{}
	filtered := []cryptox.IssuerRecoveryAuthority{}
	for _, x := range p.Authorities {
		if x.Grant.Grant.SubjectDeviceID != a.Context.InitiatorDeviceID {
			filtered = append(filtered, x)
		}
	}
	p.Authorities = filtered
	for _, g := range f.Recovery.Accepted.Submission.Grants {
		h, e := cryptox.IssuerAuthorityHash(g)
		if e != nil {
			t.Fatal(e)
		}
		p.Targets = append(p.Targets, cryptox.IssuerTarget{EnvironmentID: g.Grant.EnvironmentID, AuthorityHash: h})
	}
	approval := cryptox.EnrollmentApprovalV4{CertificateVersion: "4", Capabilities: []string{cryptox.RecoveryAuthorityCapability}, Context: a.Context, PairingProfile: a.PairingProfile, TranscriptHash: a.TranscriptHash, Grants: a.Grants, IssuerProof: p, ApproverSignature: a.ApproverSignature, InitiatorSignature: a.InitiatorSignature}
	receipt := syncclient.EnrollmentReceiptV4{IdempotencyKey: "synthetic-cert4-protected", Approval: approval}
	b, e := json.Marshal(receipt)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := hex.DecodeString(f.Seed)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	receive := bytes.Repeat([]byte{17}, 32)
	pub, e := cryptox.DecodeBase64(a.Context.InitiatorReceivingPublicKey, 32, 32)
	if e != nil {
		t.Fatal(e)
	}
	keys := localkeys.DeviceKeys{DeviceID: a.Context.InitiatorDeviceID, SigningPublic: key.Public().(ed25519.PublicKey), SigningSeed: seed, ReceivingPublic: pub, ReceivingPrivate: receive}
	trust := localkeys.TrustContext{Endpoint: "https://synthetic.example.invalid", AccountID: a.Context.AccountID, AccountGeneration: 1, DeviceID: keys.DeviceID, SigningPublic: keys.SigningPublic, ReceivingPublic: pub, CertificateVersion: "4", PairingProfile: a.PairingProfile, EnrollmentCertificate: b, EnrollmentKey: receipt.IdempotencyKey, Accepted: true}
	v, e := verifiedStoredContext(trust, keys)
	if e != nil {
		t.Fatal(e)
	}
	v.Close()
	for _, kind := range []string{"pending", "wrong-version", "manager-directory", "wrong-enrollment-id", "wrong-signing-key", "changed-issuer-proof"} {
		t.Run(kind, func(t *testing.T) {
			bad := trust
			switch kind {
			case "pending":
				bad.Accepted = false
			case "wrong-version":
				bad.CertificateVersion = "3"
			case "manager-directory":
				bad.Managers = map[string][]byte{"directory": bytes.Repeat([]byte{55}, 32)}
			case "wrong-enrollment-id":
				bad.EnrollmentKey = "other-enrollment"
			case "wrong-signing-key":
				bad.SigningPublic = bytes.Repeat([]byte{44}, 32)
			case "changed-issuer-proof":
				copy := receipt
				copy.Approval.IssuerProof.Profile = cryptox.IssuerProofV2Profile
				bad.EnrollmentCertificate, _ = json.Marshal(copy)
			}
			if other, e := verifiedStoredContext(bad, keys); e == nil {
				other.Close()
				t.Fatal("stored cert4 accepted pending, downgrade or modified protected source")
			}
		})
	}
}
