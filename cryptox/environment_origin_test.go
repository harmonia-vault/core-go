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
	"time"
)

type originFixture struct {
	SyntheticNow          int64                `json:"syntheticNow"`
	SigningSeeds          map[string]string    `json:"syntheticSigningSeedsHex"`
	Rotation              EnvironmentChangeV2  `json:"rotation"`
	Creation              EnvironmentChangeV2  `json:"creation"`
	Approval              EnrollmentApprovalV3 `json:"approval"`
	RotationSigningHex    string               `json:"rotationSigningHex"`
	RotationHash          string               `json:"rotationHash"`
	CreationSigningHex    string               `json:"creationSigningHex"`
	ProofCanonicalHex     string               `json:"proofCanonicalHex"`
	ProofHash             string               `json:"proofHash"`
	CertificateSigningHex string               `json:"certificateSigningHex"`
}

func makeOriginFixture(t *testing.T) originFixture {
	t.Helper()
	old, _ := issuerFixture(t)
	aKey := ed25519.NewKeyFromSeed(mustHex(t, old.SigningSeeds["A"]))
	bKey := ed25519.NewKeyFromSeed(mustHex(t, old.SigningSeeds["B"]))
	cKey := ed25519.NewKeyFromSeed(mustHex(t, old.SigningSeeds["C"]))
	old.SigningSeeds["D"] = strings.Repeat("05", 32)
	dKey := ed25519.NewKeyFromSeed(mustHex(t, old.SigningSeeds["D"]))
	oldA := old.Approval.IssuerProof.Authorities[0].Grant
	oldB := old.Approval.IssuerProof.Authorities[1].Grant
	if oldA.Grant.SubjectDeviceID != "device-A" {
		oldA, oldB = oldB, oldA
	}
	oldB.Grant.ExpiresAt = "2030000500"
	s, e := SignGrant(oldB.Grant, aKey)
	if e != nil {
		t.Fatal(e)
	}
	oldB = GrantToWire(s)
	path := old.Approval.IssuerProof.Path[0]
	path.Approval.Grants = []SignedGrantWire{oldB}
	pc, e := path.Approval.Certificate()
	if e != nil {
		t.Fatal(e)
	}
	path.Approval.ApproverSignature, e = SignEnrollmentCertificate(pc, aKey)
	if e != nil {
		t.Fatal(e)
	}
	path.Approval.InitiatorSignature, e = SignEnrollmentCertificate(pc, bKey)
	if e != nil {
		t.Fatal(e)
	}
	signG := func(g Grant, k ed25519.PrivateKey) SignedGrantWire {
		s, e := SignGrant(g, k)
		if e != nil {
			t.Fatal(e)
		}
		return GrantToWire(s)
	}
	newA := oldA.Grant
	newA.KeyVersion = "2"
	newA.GrantGeneration = "2"
	newA.IssuerDeviceID = "device-B"
	newA.IdempotencyKey = "rotate-A"
	ga := signG(newA, bKey)
	newB := oldB.Grant
	newB.KeyVersion = "2"
	newB.GrantGeneration = "2"
	newB.IssuerDeviceID = "device-B"
	newB.IdempotencyKey = "rotate-B"
	gb := signG(newB, bKey)
	priorC := old.Approval.Grants[0].Grant
	priorC.IssuerDeviceID = "device-A"
	priorC.IdempotencyKey = "initial-C-ro"
	priorC.ExpiresAt = "0"
	priorC.Role = "ro"
	oldC := signG(priorC, aKey)
	cx := old.Approval.Context
	cx.SessionID = "archive-C"
	cx.ApproverDeviceID = "device-A"
	cx.ApproverSigningPublicKey = oldA.Grant.SubjectSigningPublicKey
	cx.ApproverReceivingPublicKey = oldA.Grant.SubjectReceivingPublicKey
	ac := EnrollmentApproval{Context: cx, PairingProfile: old.Approval.PairingProfile, TranscriptHash: old.Approval.TranscriptHash, Grants: []SignedGrantWire{oldC}}
	acc, e := ac.Certificate()
	if e != nil {
		t.Fatal(e)
	}
	ac.ApproverSignature, e = SignEnrollmentCertificate(acc, aKey)
	if e != nil {
		t.Fatal(e)
	}
	ac.InitiatorSignature, e = SignEnrollmentCertificate(acc, cKey)
	if e != nil {
		t.Fatal(e)
	}
	newC := oldC.Grant
	newC.IssuerDeviceID = "device-B"
	newC.IdempotencyKey = "rotate-C"
	newC.KeyVersion = "2"
	newC.GrantGeneration = "2"
	grc := signG(newC, bKey)
	change := EnvironmentChange{AccountID: oldA.Grant.AccountID, AccountGeneration: "1", DeviceID: "device-B", EnvironmentID: oldA.Grant.EnvironmentID, Operation: "rotate", AuthorityEnvironmentID: oldA.Grant.EnvironmentID, AuthorityKeyVersion: "1", AuthorityGrantGeneration: "1", PreviousKeyVersion: "1", KeyVersion: "2", ExpectedSequence: "10", IdempotencyKey: "rotate-origin", RecoveryGeneration: "1", RecoveryEnvelope: EncodeBase64(make([]byte, 80)), Grants: []SignedGrantWire{ga, gb, grc}, Mutations: []SignedMutationWire{}}
	sc, e := SignEnvironmentChange(change, bKey)
	if e != nil {
		t.Fatal(e)
	}
	rotation, e := NewEnvironmentChangeV2(sc, oldB, []SignedGrantWire{oldA, oldB, oldC}, bKey)
	if e != nil {
		t.Fatal(e)
	}
	rh, _ := EnvironmentOriginHash(rotation.Origin)
	newY := oldB.Grant
	newY.EnvironmentID = "environment-Y"
	newY.IssuerDeviceID = "device-B"
	newY.IdempotencyKey = "create-Y-grant"
	gy := signG(newY, bKey)
	creationC := change
	creationC.EnvironmentID = "environment-Y"
	creationC.Operation = "create"
	creationC.LabelPayload = EncodeBase64(make([]byte, 40))
	creationC.PreviousKeyVersion = "0"
	creationC.KeyVersion = "1"
	creationC.ExpectedSequence = "11"
	creationC.IdempotencyKey = "create-Y"
	creationC.Grants = []SignedGrantWire{gy}
	cc, e := SignEnvironmentChange(creationC, bKey)
	if e != nil {
		t.Fatal(e)
	}
	creation, e := NewEnvironmentChangeV2(cc, oldB, nil, bKey)
	if e != nil {
		t.Fatal(e)
	}
	yh, _ := EnvironmentOriginHash(creation.Origin)
	ha, _ := IssuerAuthorityHash(oldA)
	hb, _ := IssuerAuthorityHash(oldB)
	hgb, _ := IssuerAuthorityHash(gb)
	hc, _ := IssuerAuthorityHash(oldC)
	p := IssuerProofV2{Profile: IssuerProofV2Profile, AccountID: old.Approval.Context.AccountID, AccountGeneration: "1", TrustRoot: old.Approval.IssuerProof.TrustRoot, Path: []IssuerEnrollment{path}, Authorities: []IssuerAuthorityV2{{Grant: oldA}, {Grant: oldB, ParentHash: ha}, {Grant: ga, ParentHash: hb, OriginHash: rh, PreviousGrantHash: ha}, {Grant: gb, ParentHash: hb, OriginHash: rh, PreviousGrantHash: hb}, {Grant: gy, ParentHash: hb, OriginHash: yh}, {Grant: oldC, ParentHash: ha}, {Grant: grc, ParentHash: hb, OriginHash: rh, PreviousGrantHash: hc}}, Targets: []IssuerTarget{{oldA.Grant.EnvironmentID, hgb}}, Origins: []SignedEnvironmentOrigin{rotation.Origin, creation.Origin}, IdentityPaths: [][]IssuerEnrollment{{{CertificateVersion: "1", Approval: ac}}}}
	grantC := old.Approval.Grants[0].Grant
	grantC.KeyVersion = "2"
	grantC.ExpiresAt = oldB.Grant.ExpiresAt
	grantC.IdempotencyKey = "enroll-D-v3"
	grantC.SubjectDeviceID = "device-D"
	grantC.SubjectSigningPublicKey = EncodeBase64(dKey.Public().(ed25519.PublicKey))
	dk, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{15}, 32))
	grantC.SubjectReceivingPublicKey = EncodeBase64(dk.PublicKey().Bytes())
	gc := signG(grantC, bKey)
	app := EnrollmentApprovalV3{CertificateVersion: "3", Context: old.Approval.Context, PairingProfile: old.Approval.PairingProfile, TranscriptHash: old.Approval.TranscriptHash, Grants: []SignedGrantWire{gc}, IssuerProof: p}
	app.Context.InitiatorDeviceID = grantC.SubjectDeviceID
	app.Context.InitiatorSigningPublicKey = grantC.SubjectSigningPublicKey
	app.Context.InitiatorReceivingPublicKey = grantC.SubjectReceivingPublicKey
	cert, e := app.Certificate()
	if e != nil {
		t.Fatal(e)
	}
	app.ApproverSignature, e = SignEnrollmentCertificateV3(cert, bKey)
	if e != nil {
		t.Fatal(e)
	}
	app.InitiatorSignature, e = SignEnrollmentCertificateV3(cert, dKey)
	if e != nil {
		t.Fatal(e)
	}
	rb, _ := rotation.Origin.Origin.SigningBytes()
	cb, _ := creation.Origin.Origin.SigningBytes()
	pb, _ := p.CanonicalBytes()
	ph, _ := p.Hash()
	eb, _ := cert.SigningBytes()
	return originFixture{old.Now, old.SigningSeeds, rotation, creation, app, hex.EncodeToString(rb), rh, hex.EncodeToString(cb), hex.EncodeToString(pb), ph, hex.EncodeToString(eb)}
}
func originAnchor(v originFixture) ConfirmedEnrollmentAnchor {
	return ConfirmedEnrollmentAnchor{v.Approval.Context, v.Approval.TranscriptHash}
}
func originPin(v originFixture) PinnedIssuerRoot {
	r := v.Approval.IssuerProof.TrustRoot
	return PinnedIssuerRoot{v.Approval.Context.AccountID, "1", r.RootDeviceID, r.RootSigningPublicKey, r.RootReceivingPublicKey}
}
func cloneOriginFixture(t *testing.T, v originFixture) originFixture {
	t.Helper()
	b, _ := json.Marshal(v)
	var c originFixture
	if e := json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	return c
}
func TestEnvironmentOriginDualParentsAndV3(t *testing.T) {
	v := makeOriginFixture(t)
	p, e := VerifyCompletedEnrollmentV3(originAnchor(v), v.Approval)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyEnrollmentApprovalV3(originAnchor(v), v.Approval, time.Unix(v.SyntheticNow, 0)); e != nil {
		t.Fatal(e)
	}
	// 临时 B 保留 A 已有的永久权限；不能按普通委派期限错误拒绝它。
	if v.Rotation.Origin.Origin.After[0].ExpiresAt != "0" || v.Rotation.Origin.Origin.After[1].ExpiresAt == "0" {
		t.Fatal("合成永久/临时边界错误")
	}
	if e = p.VerifyHistoricalGrant(v.Rotation.Change.Grants[0]); e != nil {
		t.Fatal("合法轮换后的永久 A 权限未通过", e)
	}
	if e = p.VerifyHistoricalGrant(v.Creation.Change.Grants[0]); e != nil {
		t.Fatal("B 新建环境来源未通过", e)
	}
	for _, before := range v.Rotation.Origin.Origin.Before {
		if before.GrantHash == "" {
			t.Fatal("缺旧接收者边")
		}
	}
	if os.Getenv("HARMONIA_WRITE_SYNTHETIC_ORIGIN_VECTOR") == "1" {
		b, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		b = append(b, '\n')
		for _, path := range []string{"testdata/environment-origin-v1.json", "../../protocol/vectors/environment-origin-v1.json"} {
			if e = os.WriteFile(path, b, 0644); e != nil {
				t.Fatal(e)
			}
		}
	}
}
func TestEnvironmentOriginRejectsEverySignedFieldReplacement(t *testing.T) {
	v := makeOriginFixture(t)
	key, _ := DecodeBase64(v.Approval.Context.ApproverSigningPublicKey, 32, 32)
	mutations := map[string]func(*EnvironmentOrigin){"account": func(o *EnvironmentOrigin) { o.AccountID = "other" }, "generation": func(o *EnvironmentOrigin) { o.AccountGeneration = "2" }, "actor": func(o *EnvironmentOrigin) { o.ActorDeviceID = "device-A" }, "environment": func(o *EnvironmentOrigin) { o.EnvironmentID = "other" }, "authorityEnv": func(o *EnvironmentOrigin) { o.AuthorityEnvironmentID = "other" }, "authorityKV": func(o *EnvironmentOrigin) { o.AuthorityKeyVersion = "2" }, "authorityGeneration": func(o *EnvironmentOrigin) { o.AuthorityGrantGeneration = "2" }, "operation": func(o *EnvironmentOrigin) { o.Operation = "create" }, "oldKV": func(o *EnvironmentOrigin) { o.PreviousKeyVersion = "2" }, "newKV": func(o *EnvironmentOrigin) { o.KeyVersion = "3" }, "sequence": func(o *EnvironmentOrigin) { o.ExpectedSequence = "12" }, "idempotency": func(o *EnvironmentOrigin) { o.IdempotencyKey = "other" }, "changeHash": func(o *EnvironmentOrigin) { o.ChangeHash = strings.Repeat("0", 64) }, "authorityHash": func(o *EnvironmentOrigin) { o.AuthorityHash = strings.Repeat("0", 64) }, "before": func(o *EnvironmentOrigin) { o.Before[0].GrantHash = strings.Repeat("0", 64) }, "after": func(o *EnvironmentOrigin) { o.After[0].GrantHash = strings.Repeat("0", 64) }}
	for name, f := range mutations {
		t.Run(name, func(t *testing.T) {
			c := cloneOriginFixture(t, v)
			f(&c.Rotation.Origin.Origin)
			if VerifyEnvironmentOrigin(c.Rotation.Origin, key) == nil {
				t.Fatal("沿用签名接受了替换")
			}
		})
	}
}
func TestIssuerProofV2RejectsMissingConflictingSources(t *testing.T) {
	v := makeOriginFixture(t)
	mutations := map[string]func(*IssuerProofV2){"missingActor": func(p *IssuerProofV2) { p.Authorities = append(p.Authorities[:1], p.Authorities[2:]...) }, "missingRecipient": func(p *IssuerProofV2) { p.Authorities = p.Authorities[1:] }, "missingOrigin": func(p *IssuerProofV2) { p.Origins = nil }, "wrongRecipientEdge": func(p *IssuerProofV2) { p.Authorities[2].PreviousGrantHash = p.Authorities[1].ParentHash + "0" }, "wrongActorEdge": func(p *IssuerProofV2) { p.Authorities[2].ParentHash = p.Authorities[1].ParentHash }, "wrongPub": func(p *IssuerProofV2) {
		p.Authorities[2].Grant.Grant.SubjectReceivingPublicKey = EncodeBase64(make([]byte, 32))
	}, "crossGeneration": func(p *IssuerProofV2) { p.AccountGeneration = "2" }, "untrustedActorDirectory": func(p *IssuerProofV2) { p.Path = nil }, "duplicateBranch": func(p *IssuerProofV2) { p.IdentityPaths = [][]IssuerEnrollment{p.Path, p.Path} }, "cycle": func(p *IssuerProofV2) {
		h, _ := IssuerAuthorityHash(p.Authorities[1].Grant)
		p.Authorities[1].ParentHash = h
	}, "extraDataProfile": func(p *IssuerProofV2) { p.Profile = IssuerProofProfile }}
	for name, f := range mutations {
		t.Run(name, func(t *testing.T) {
			c := cloneOriginFixture(t, v)
			f(&c.Approval.IssuerProof)
			if _, e := VerifyIssuerEvidenceV2(originPin(v), c.Approval.IssuerProof, proofGenesisV2(v.Approval.IssuerProof)...); e == nil {
				t.Fatal("接受缺失/冲突来源")
			}
		})
	}
}
func TestEnvironmentOriginControlOnlyAndStrictV3(t *testing.T) {
	v := makeOriginFixture(t)
	b, _ := json.Marshal(v.Rotation.Origin)
	for _, secretField := range []string{"labelPayload", "recoveryEnvelope", "mutations", "ciphertext"} {
		if strings.Contains(string(b), secretField) {
			t.Fatal("来源泄露数据字段")
		}
	}
	full, _ := json.Marshal(v.Approval)
	if _, e := DecodeEnrollmentApprovalV3(full); e != nil {
		t.Fatal(e)
	}
	injected := append([]byte(`{"shortCode":"12345678",`), full[1:]...)
	if _, e := DecodeEnrollmentApprovalV3(injected); e == nil {
		t.Fatal("未知字段接受")
	}
	if _, e := DecodeEnrollmentApprovalV2(full); e == nil {
		t.Fatal("旧profile静默接受新证明")
	}
	cert, _ := v.Approval.Certificate()
	key, _ := DecodeBase64(v.Approval.Context.ApproverSigningPublicKey, 32, 32)
	if VerifyEnrollmentCertificateV2(EnrollmentCertificateV2{cert.EnrollmentCertificate, cert.IssuerProofHash}, v.Approval.ApproverSignature, key) == nil {
		t.Fatal("证书v3降级v2")
	}
}
