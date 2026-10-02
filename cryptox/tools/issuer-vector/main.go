// 生成公开合成向量，不读取环境变量、真实账号或凭据。
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
func key(n byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
func recv(n byte) *ecdh.PrivateKey {
	return must(ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{n}, 32)))
}
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "需要明确的合成向量输出路径")
		os.Exit(2)
	}
	const account = "account-chain"
	const generation = "1"
	const environment = "env-fixture"
	const now int64 = 2030000000
	a, b, c := key(1), key(2), key(3)
	ar, br, cr := recv(11), recv(12), recv(13)
	recovery := must(cryptox.DeriveRecoveryKeys(bytes.Repeat([]byte{4}, 32), account, generation, "1"))
	public := func(k ed25519.PrivateKey) string { return cryptox.EncodeBase64(k.Public().(ed25519.PublicKey)) }
	root := must(cryptox.SignTrustRoot(account, generation, cryptox.TrustRoot{RootDeviceID: "device-A", RootSigningPublicKey: public(a), RootReceivingPublicKey: cryptox.EncodeBase64(ar.PublicKey().Bytes()), RecoveryGeneration: "1", RecoverySigningPublicKey: cryptox.EncodeBase64(recovery.SigningPublic), RecoveryReceivingPublicKey: cryptox.EncodeBase64(recovery.ReceivingPublic)}, recovery.SigningPrivate))
	envKey := bytes.Repeat([]byte{9}, 32)
	grant := func(issuerID, subjectID string, subjectKey ed25519.PrivateKey, receiving *ecdh.PrivateKey, role, expiry, id string, issuerKey ed25519.PrivateKey) cryptox.SignedGrantWire {
		g := cryptox.Grant{AccountID: account, AccountGeneration: generation, IssuerDeviceID: issuerID, SubjectDeviceID: subjectID, SubjectSigningPublicKey: public(subjectKey), SubjectReceivingPublicKey: cryptox.EncodeBase64(receiving.PublicKey().Bytes()), EnvironmentID: environment, KeyVersion: "1", GrantGeneration: "1", Role: role, ExpiresAt: expiry, IdempotencyKey: id}
		g.Envelope = cryptox.EncodeBase64(must(cryptox.WrapEnvironmentKey(envKey, cryptox.EnvelopeContext{AccountID: account, AccountGeneration: generation, EnvironmentID: environment, KeyVersion: "1", RecipientType: "device", RecipientID: subjectID, RecipientGeneration: "1", RecipientPublicKey: g.SubjectReceivingPublicKey})))
		return cryptox.GrantToWire(must(cryptox.SignGrant(g, issuerKey)))
	}
	aa := grant("device-A", "device-A", a, ar, "admin", "0", "root-admin", a)
	ab := grant("device-A", "device-B", b, br, "admin", "0", "B-admin", a)
	bc := grant("device-B", "device-C", c, cr, "ro", strconv.FormatInt(now+300, 10), "C-read", b)
	context := func(session string, nonce byte, expires int64, initiatorID string, initiatorKey ed25519.PrivateKey, initiatorReceive *ecdh.PrivateKey, approverID string, approverKey ed25519.PrivateKey, approverReceive *ecdh.PrivateKey) cryptox.EnrollmentContext {
		return cryptox.EnrollmentContext{AccountID: account, AccountGeneration: generation, Purpose: "enroll-device", SessionID: session, ChallengeNonce: cryptox.EncodeBase64(bytes.Repeat([]byte{nonce}, 32)), ExpiresAt: strconv.FormatInt(expires, 10), InitiatorDeviceID: initiatorID, InitiatorSigningPublicKey: public(initiatorKey), InitiatorReceivingPublicKey: cryptox.EncodeBase64(initiatorReceive.PublicKey().Bytes()), ApproverDeviceID: approverID, ApproverSigningPublicKey: public(approverKey), ApproverReceivingPublicKey: cryptox.EncodeBase64(approverReceive.PublicKey().Bytes())}
	}
	old := cryptox.EnrollmentApproval{Context: context("pairing-B", 21, now-100, "device-B", b, br, "device-A", a, ar), PairingProfile: cryptox.EnrollmentPairingProfile, TranscriptHash: hex.EncodeToString(bytes.Repeat([]byte{31}, 32)), Grants: []cryptox.SignedGrantWire{ab}}
	oldCert := must(old.Certificate())
	old.ApproverSignature = must(cryptox.SignEnrollmentCertificate(oldCert, a))
	old.InitiatorSignature = must(cryptox.SignEnrollmentCertificate(oldCert, b))
	ah, bh := must(cryptox.IssuerAuthorityHash(aa)), must(cryptox.IssuerAuthorityHash(ab))
	proof := cryptox.IssuerProof{Profile: cryptox.IssuerProofProfile, AccountID: account, AccountGeneration: generation, TrustRoot: root, Path: []cryptox.IssuerEnrollment{{CertificateVersion: "1", IssuerProofHash: "", Approval: old}}, Authorities: []cryptox.IssuerAuthority{{Grant: ab, ParentHash: ah}, {Grant: aa, ParentHash: ""}}, Targets: []cryptox.IssuerTarget{{EnvironmentID: environment, AuthorityHash: bh}}}
	current := cryptox.EnrollmentApprovalV2{CertificateVersion: "2", Context: context("pairing-C", 22, now+90, "device-C", c, cr, "device-B", b, br), PairingProfile: cryptox.EnrollmentPairingProfile, TranscriptHash: hex.EncodeToString(bytes.Repeat([]byte{32}, 32)), Grants: []cryptox.SignedGrantWire{bc}, IssuerProof: proof}
	cert := must(current.Certificate())
	current.ApproverSignature = must(cryptox.SignEnrollmentCertificateV2(cert, b))
	current.InitiatorSignature = must(cryptox.SignEnrollmentCertificateV2(cert, c))
	mutation := cryptox.Mutation{AccountID: account, AccountGeneration: generation, DeviceID: "device-A", EnvironmentID: environment, KeyVersion: "1", GrantGeneration: "1", Operation: "put", IdempotencyKey: "historical-write", Name: "FIXTURE_KEY"}
	mutation.Payload = cryptox.EncodeBase64(must(cryptox.EncryptValue(envKey, cryptox.ValueContext{AccountID: account, AccountGeneration: generation, EnvironmentID: environment, KeyVersion: "1", Name: mutation.Name}, []byte("synthetic-only"))))
	signedMutation := must(cryptox.SignMutation(mutation, a))
	data := map[string]any{"description": "公开合成 A→B→C 签发者证明；不是 PAKE 原语向量或当前权限证明。HPKE/AEAD 为真实原语生成。", "syntheticNow": now, "syntheticSigningSeedsHex": map[string]string{"A": hex.EncodeToString(a.Seed()), "B": hex.EncodeToString(b.Seed()), "C": hex.EncodeToString(c.Seed())}, "syntheticReceivingPrivateKeysHex": map[string]string{"A": hex.EncodeToString(ar.Bytes()), "B": hex.EncodeToString(br.Bytes()), "C": hex.EncodeToString(cr.Bytes())}, "syntheticRecoverySeedHex": hex.EncodeToString(bytes.Repeat([]byte{4}, 32)), "syntheticEnvironmentKeyHex": hex.EncodeToString(envKey), "approval": current, "proofCanonicalHex": hex.EncodeToString(must(proof.CanonicalBytes())), "proofHash": must(proof.Hash()), "certificateSigningHex": hex.EncodeToString(must(cert.SigningBytes())), "authorityHashes": map[string]string{"A": ah, "B": bh}, "historicalMutation": signedMutation, "historicalAuthorization": aa}
	out := must(json.MarshalIndent(data, "", "  "))
	out = append(out, '\n')
	if err := os.WriteFile(os.Args[1], out, 0644); err != nil {
		panic(err)
	}
}
