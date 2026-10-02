package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type issuerProofVector struct {
	Now                     int64                `json:"syntheticNow"`
	SigningSeeds            map[string]string    `json:"syntheticSigningSeedsHex"`
	ReceivingKeys           map[string]string    `json:"syntheticReceivingPrivateKeysHex"`
	EnvironmentKey          string               `json:"syntheticEnvironmentKeyHex"`
	Approval                EnrollmentApprovalV2 `json:"approval"`
	ProofCanonicalHex       string               `json:"proofCanonicalHex"`
	ProofHash               string               `json:"proofHash"`
	CertificateSigningHex   string               `json:"certificateSigningHex"`
	AuthorityHashes         map[string]string    `json:"authorityHashes"`
	HistoricalMutation      SignedMutation       `json:"historicalMutation"`
	HistoricalAuthorization SignedGrantWire      `json:"historicalAuthorization"`
}

func issuerFixture(t *testing.T) (issuerProofVector, ConfirmedEnrollmentAnchor) {
	t.Helper()
	var v issuerProofVector
	readVector(t, "issuer-proof-v1.json", &v)
	anchor := ConfirmedEnrollmentAnchor{v.Approval.Context, v.Approval.TranscriptHash}
	// 测试锚的设备公钥由公开合成私钥独立重建，不从 proof 的 issuer 目录取得。
	b := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["B"]))
	c := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["C"]))
	if anchor.Context.ApproverSigningPublicKey != EncodeBase64(b.Public().(ed25519.PublicKey)) || anchor.Context.InitiatorSigningPublicKey != EncodeBase64(c.Public().(ed25519.PublicKey)) {
		t.Fatal("合成锚公钥不符")
	}
	return v, anchor
}
func resignIssuerApproval(t *testing.T, a *EnrollmentApprovalV2, v issuerProofVector) {
	t.Helper()
	c, err := a.Certificate()
	if err != nil {
		return
	}
	b := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["B"]))
	d := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["C"]))
	a.ApproverSignature, err = SignEnrollmentCertificateV2(c, b)
	if err != nil {
		t.Fatal(err)
	}
	a.InitiatorSignature, err = SignEnrollmentCertificateV2(c, d)
	if err != nil {
		t.Fatal(err)
	}
}
func TestIssuerProofCrossLanguageAndHistoricalAncestorRead(t *testing.T) {
	v, anchor := issuerFixture(t)
	b, err := v.Approval.IssuerProof.CanonicalBytes()
	if err != nil || hex.EncodeToString(b) != v.ProofCanonicalHex {
		t.Fatal("proof固定字节不同", err)
	}
	h, err := v.Approval.IssuerProof.Hash()
	if err != nil || h != v.ProofHash {
		t.Fatal("proof摘要不同", err)
	}
	c, err := v.Approval.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	b, err = c.SigningBytes()
	if err != nil || hex.EncodeToString(b) != v.CertificateSigningHex {
		t.Fatal("v2证书固定字节不同", err)
	}
	verified, err := VerifyEnrollmentApprovalV2(anchor, v.Approval, time.Unix(v.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCompletedEnrollmentV2(anchor, v.Approval); err != nil {
		t.Fatal(err)
	}
	bindings := verified.IssuerBindings()
	if len(bindings) != 2 || bindings[0].DeviceID != "device-A" || bindings[1].DeviceID != "device-B" {
		t.Fatal("未取得精确逐环境祖先来源")
	}
	if err := verified.VerifyDelegatedGrant(v.HistoricalAuthorization, v.AuthorityHashes["A"]); err != nil {
		t.Fatal(err)
	}
	if err := verified.VerifyDelegatedGrant(v.Approval.Grants[0], v.AuthorityHashes["B"]); err != nil {
		t.Fatal(err)
	}
	a := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["A"]))
	if err := VerifyMutation(v.HistoricalMutation, a.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	g := v.Approval.Grants[0].Grant
	packet, err := DecodeBase64(g.Envelope, 80, 80)
	if err != nil {
		t.Fatal(err)
	}
	env, err := UnwrapEnvironmentKey(mustHex(t, v.ReceivingKeys["C"]), EnvelopeContext{g.AccountID, g.AccountGeneration, g.EnvironmentID, g.KeyVersion, "device", g.SubjectDeviceID, g.GrantGeneration, g.SubjectReceivingPublicKey}, packet)
	if err != nil || !bytes.Equal(env, mustHex(t, v.EnvironmentKey)) {
		t.Fatal("C的真实HPKE封套解密失败", err)
	}
	m := v.HistoricalMutation.Mutation
	packet, err = DecodeBase64(m.Payload, 40, MaxValueBytes+40)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecryptValue(env, ValueContext{m.AccountID, m.AccountGeneration, m.EnvironmentID, m.KeyVersion, m.Name}, packet)
	if err != nil || string(plaintext) != "synthetic-only" {
		t.Fatal("C不能验解A的历史真实密文", err)
	}
	clear(env)
	clear(plaintext)
}
func TestIssuerProofEverySignedPresentationBinding(t *testing.T) {
	v, anchor := issuerFixture(t)
	cases := map[string]func(*EnrollmentApprovalV2){
		"账号":   func(a *EnrollmentApprovalV2) { a.IssuerProof.AccountID = "other" },
		"账号代际": func(a *EnrollmentApprovalV2) { a.IssuerProof.AccountGeneration = "2" },
		"根设备":  func(a *EnrollmentApprovalV2) { a.IssuerProof.TrustRoot.RootDeviceID = "other" },
		"根接收公钥": func(a *EnrollmentApprovalV2) {
			a.IssuerProof.TrustRoot.RootReceivingPublicKey = EncodeBase64(bytes.Repeat([]byte{90}, 32))
		},
		"父签名公钥": func(a *EnrollmentApprovalV2) {
			a.IssuerProof.Path[0].Approval.Context.ApproverSigningPublicKey = EncodeBase64(bytes.Repeat([]byte{91}, 32))
		},
		"子接收公钥": func(a *EnrollmentApprovalV2) {
			a.IssuerProof.Path[0].Approval.Context.InitiatorReceivingPublicKey = EncodeBase64(bytes.Repeat([]byte{92}, 32))
		},
		"旧用途": func(a *EnrollmentApprovalV2) { a.IssuerProof.Path[0].Approval.Context.Purpose = "other" },
		"旧会话": func(a *EnrollmentApprovalV2) { a.IssuerProof.Path[0].Approval.Context.SessionID = "other" },
		"旧nonce": func(a *EnrollmentApprovalV2) {
			a.IssuerProof.Path[0].Approval.Context.ChallengeNonce = EncodeBase64(bytes.Repeat([]byte{93}, 32))
		},
		"旧期限":          func(a *EnrollmentApprovalV2) { a.IssuerProof.Path[0].Approval.Context.ExpiresAt = "2030000100" },
		"授权摘要":         func(a *EnrollmentApprovalV2) { a.IssuerProof.Path[0].Approval.Grants[0].Grant.Role = "ro" },
		"父证据":          func(a *EnrollmentApprovalV2) { a.IssuerProof.Authorities[0].ParentHash = strings.Repeat("0", 64) },
		"目标证据":         func(a *EnrollmentApprovalV2) { a.IssuerProof.Targets[0].AuthorityHash = strings.Repeat("0", 64) },
		"本次transcript": func(a *EnrollmentApprovalV2) { a.TranscriptHash = strings.Repeat("0", 64) },
		"本次版本":         func(a *EnrollmentApprovalV2) { a.CertificateVersion = "1" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			a := cloneJSON(t, v.Approval)
			change(&a)
			if _, err := VerifyCompletedEnrollmentV2(anchor, a); err == nil {
				t.Fatal("接受服务器修改的presentation")
			}
		})
	}
	wrong := anchor
	wrong.Context.ApproverReceivingPublicKey = EncodeBase64(bytes.Repeat([]byte{88}, 32))
	if _, err := VerifyCompletedEnrollmentV2(wrong, v.Approval); err == nil {
		t.Fatal("接受服务器替换PAKE锚")
	}
}
func TestIssuerProofResignedInvalidGraphsAndEnvironmentScope(t *testing.T) {
	v, anchor := issuerFixture(t)
	cases := map[string]func(*EnrollmentApprovalV2){
		"缺路径":         func(a *EnrollmentApprovalV2) { a.IssuerProof.Path = nil },
		"重复路径":        func(a *EnrollmentApprovalV2) { a.IssuerProof.Path = append(a.IssuerProof.Path, a.IssuerProof.Path[0]) },
		"循环authority": func(a *EnrollmentApprovalV2) { a.IssuerProof.Authorities[1].ParentHash = v.AuthorityHashes["B"] },
		"重复authority": func(a *EnrollmentApprovalV2) {
			a.IssuerProof.Authorities = append(a.IssuerProof.Authorities, a.IssuerProof.Authorities[0])
		},
		"非根无父":        func(a *EnrollmentApprovalV2) { a.IssuerProof.Authorities[0].ParentHash = "" },
		"缺父authority": func(a *EnrollmentApprovalV2) { a.IssuerProof.Authorities = a.IssuerProof.Authorities[:1] },
		"缺目标":         func(a *EnrollmentApprovalV2) { a.IssuerProof.Targets = nil },
		"重复目标": func(a *EnrollmentApprovalV2) {
			a.IssuerProof.Targets = append(a.IssuerProof.Targets, a.IssuerProof.Targets[0])
		},
		"目标环境偷换": func(a *EnrollmentApprovalV2) { a.IssuerProof.Targets[0].EnvironmentID = "env-other" },
		"旧域静默升级": func(a *EnrollmentApprovalV2) {
			a.IssuerProof.Path[0].CertificateVersion = "2"
			a.IssuerProof.Path[0].IssuerProofHash = strings.Repeat("0", 64)
		},
		"根双钥碰撞": func(a *EnrollmentApprovalV2) {
			a.IssuerProof.TrustRoot.RootReceivingPublicKey = a.IssuerProof.TrustRoot.RootSigningPublicKey
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			a := cloneJSON(t, v.Approval)
			change(&a)
			resignIssuerApproval(t, &a, v)
			if _, err := VerifyCompletedEnrollmentV2(anchor, a); err == nil {
				t.Fatal("即使本次签名有效也不应接受无效链")
			}
		})
	}
	verified, err := VerifyCompletedEnrollmentV2(anchor, v.Approval)
	if err != nil {
		t.Fatal(err)
	}
	other := v.Approval.Grants[0]
	other.Grant.EnvironmentID = "env-other"
	b := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["B"]))
	signed, err := SignGrant(other.Grant, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := verified.VerifyHistoricalGrant(GrantToWire(signed)); err == nil {
		t.Fatal("env-fixture Admin被全局扩展至其它环境")
	}
}
func TestIssuerProofHistoryDoesNotBecomeCurrentAuthority(t *testing.T) {
	v, anchor := issuerFixture(t)
	if _, err := VerifyEnrollmentApprovalV2(anchor, v.Approval, time.Unix(v.Now+100, 0)); err == nil {
		t.Fatal("接受过期本次挑战")
	}
	if _, err := VerifyCompletedEnrollmentV2(anchor, v.Approval); err != nil {
		t.Fatal("历史双签不应随时间不能验签", err)
	}
	a := cloneJSON(t, v.Approval)
	a.InitiatorSignature = ""
	if _, err := VerifyEnrollmentApprovalV2(anchor, a, time.Unix(v.Now, 0)); err != nil {
		t.Fatal("管理批准阶段应允许尚未完成的新设备签名", err)
	}
	if _, err := VerifyCompletedEnrollmentV2(anchor, a); err == nil {
		t.Fatal("未完成批准变成可信收据")
	}
	a = cloneJSON(t, v.Approval)
	authority := a.IssuerProof.Authorities[0]
	authority.Grant.Grant.ExpiresAt = "2029999999"
	authority.Grant.Grant.GrantGeneration = "2"
	authority.Grant.Grant.IdempotencyKey = "B-expired-new"
	root := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["A"]))
	signed, err := SignGrant(authority.Grant.Grant, root)
	if err != nil {
		t.Fatal(err)
	}
	a.IssuerProof.Authorities[0].Grant = GrantToWire(signed)
	h, err := IssuerAuthorityHash(a.IssuerProof.Authorities[0].Grant)
	if err != nil {
		t.Fatal(err)
	}
	a.IssuerProof.Targets[0].AuthorityHash = h
	resignIssuerApproval(t, &a, v)
	if _, err := VerifyEnrollmentApprovalV2(anchor, a, time.Unix(v.Now, 0)); err == nil {
		t.Fatal("过期历史Admin授权产生新的有效授权")
	}
}
func TestEnrollmentV2PinnedRootPreSignAndStrictCompatibility(t *testing.T) {
	v, anchor := issuerFixture(t)
	a := cloneJSON(t, v.Approval)
	a.ApproverSignature = ""
	a.InitiatorSignature = ""
	r := a.IssuerProof.TrustRoot
	pin := PinnedIssuerRoot{a.Context.AccountID, a.Context.AccountGeneration, r.RootDeviceID, r.RootSigningPublicKey, r.RootReceivingPublicKey}
	key := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["B"]))
	signed, err := SignEnrollmentApprovalV2(a, pin, anchor, key, time.Unix(v.Now, 0))
	if err != nil || signed.ApproverSignature != v.Approval.ApproverSignature {
		t.Fatal("本地根pin预签不一致", err)
	}
	pin.SigningPublicKey = anchor.Context.ApproverSigningPublicKey
	if _, err := SignEnrollmentApprovalV2(a, pin, anchor, key, time.Unix(v.Now, 0)); err == nil {
		t.Fatal("手机盲签服务器假根")
	}
	cert, err := v.Approval.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyEnrollmentCertificate(cert.EnrollmentCertificate, v.Approval.ApproverSignature, key.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("v2签名降级成v1")
	}
	data, err := json.Marshal(v.Approval)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEnrollmentApprovalV2(data); err != nil {
		t.Fatal(err)
	}
	var unknown map[string]any
	if err := json.Unmarshal(data, &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["shortCode"] = "synthetic-forbidden"
	data, err = json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEnrollmentApprovalV2(data); err == nil {
		t.Fatal("接受未知字段")
	}
	legacy, err := json.Marshal(v.Approval.IssuerProof.Path[0].Approval)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEnrollmentApprovalV2(legacy); err == nil {
		t.Fatal("legacy默默扩展Managers")
	}
	if _, err := DecodeEnrollmentApprovalV2(bytes.Repeat([]byte{' '}, MaxIssuerProofBytes+1)); err == nil {
		t.Fatal("接受超限编码")
	}
	p := cloneJSON(t, v.Approval.IssuerProof)
	p.Path = make([]IssuerEnrollment, MaxIssuerProofPath+1)
	if _, err := p.Hash(); err == nil {
		t.Fatal("接受超长路径")
	}
	p = cloneJSON(t, v.Approval.IssuerProof)
	p.Authorities = make([]IssuerAuthority, MaxIssuerAuthorities+1)
	if _, err := p.Hash(); err == nil {
		t.Fatal("接受超长授权图")
	}
}

func TestIssuerProofGenerationForkAndUnsupportedRotation(t *testing.T) {
	v, anchor := issuerFixture(t)
	root := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["A"]))
	for _, name := range []string{"generation-fork", "idempotency-fork", "unproved-key-rotation"} {
		t.Run(name, func(t *testing.T) {
			a := cloneJSON(t, v.Approval)
			g := a.IssuerProof.Authorities[0].Grant.Grant
			switch name {
			case "generation-fork":
				g.ExpiresAt = "2030000500"
			case "idempotency-fork":
				g.GrantGeneration = "2"
			case "unproved-key-rotation":
				g.GrantGeneration = "2"
				g.KeyVersion = "2"
				g.IdempotencyKey = "B-new-key"
			}
			signed, err := SignGrant(g, root)
			if err != nil {
				t.Fatal(err)
			}
			a.IssuerProof.Authorities[0].Grant = GrantToWire(signed)
			h, err := IssuerAuthorityHash(a.IssuerProof.Authorities[0].Grant)
			if err != nil {
				t.Fatal(err)
			}
			a.IssuerProof.Targets[0].AuthorityHash = h
			resignIssuerApproval(t, &a, v)
			if _, err := VerifyCompletedEnrollmentV2(anchor, a); err == nil {
				t.Fatal("接受分叉或未证明的跨版本授权")
			}
		})
	}
}

func TestIssuerProofArchivedV2CanBindAnotherManager(t *testing.T) {
	v, anchor := issuerFixture(t)
	b := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["B"]))
	c := ed25519.NewKeyFromSeed(mustHex(t, v.SigningSeeds["C"]))
	d := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	dr, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	a := cloneJSON(t, v.Approval)
	g := a.Grants[0].Grant
	g.Role = "admin"
	g.ExpiresAt = "0"
	signed, err := SignGrant(g, b)
	if err != nil {
		t.Fatal(err)
	}
	a.Grants[0] = GrantToWire(signed)
	resignIssuerApproval(t, &a, v)
	if _, err := VerifyCompletedEnrollmentV2(anchor, a); err != nil {
		t.Fatal(err)
	}
	oldCert, err := a.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	p := cloneJSON(t, a.IssuerProof)
	old := EnrollmentApproval{a.Context, a.PairingProfile, a.TranscriptHash, a.Grants, a.ApproverSignature, a.InitiatorSignature}
	p.Path = append(p.Path, IssuerEnrollment{"2", oldCert.IssuerProofHash, old})
	ch, err := IssuerAuthorityHash(a.Grants[0])
	if err != nil {
		t.Fatal(err)
	}
	p.Authorities = append(p.Authorities, IssuerAuthority{a.Grants[0], v.AuthorityHashes["B"]})
	p.Targets = []IssuerTarget{{"env-fixture", ch}}
	context := a.Context
	context.SessionID = "pairing-D"
	context.ChallengeNonce = EncodeBase64(bytes.Repeat([]byte{42}, 32))
	context.ApproverDeviceID = context.InitiatorDeviceID
	context.ApproverSigningPublicKey = context.InitiatorSigningPublicKey
	context.ApproverReceivingPublicKey = context.InitiatorReceivingPublicKey
	context.InitiatorDeviceID = "device-D"
	context.InitiatorSigningPublicKey = EncodeBase64(d.Public().(ed25519.PublicKey))
	context.InitiatorReceivingPublicKey = EncodeBase64(dr.PublicKey().Bytes())
	dg := g
	dg.IssuerDeviceID = "device-C"
	dg.SubjectDeviceID = context.InitiatorDeviceID
	dg.SubjectSigningPublicKey = context.InitiatorSigningPublicKey
	dg.SubjectReceivingPublicKey = context.InitiatorReceivingPublicKey
	dg.Role = "ro"
	dg.IdempotencyKey = "D-read"
	packet, err := WrapEnvironmentKey(mustHex(t, v.EnvironmentKey), EnvelopeContext{dg.AccountID, dg.AccountGeneration, dg.EnvironmentID, dg.KeyVersion, "device", dg.SubjectDeviceID, dg.GrantGeneration, dg.SubjectReceivingPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	dg.Envelope = EncodeBase64(packet)
	ds, err := SignGrant(dg, c)
	if err != nil {
		t.Fatal(err)
	}
	next := EnrollmentApprovalV2{CertificateVersion: "2", Context: context, PairingProfile: EnrollmentPairingProfile, TranscriptHash: strings.Repeat("4", 64), Grants: []SignedGrantWire{GrantToWire(ds)}, IssuerProof: p}
	nextCert, err := next.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	next.ApproverSignature, err = SignEnrollmentCertificateV2(nextCert, c)
	if err != nil {
		t.Fatal(err)
	}
	next.InitiatorSignature, err = SignEnrollmentCertificateV2(nextCert, d)
	if err != nil {
		t.Fatal(err)
	}
	nextAnchor := ConfirmedEnrollmentAnchor{context, next.TranscriptHash}
	verified, err := VerifyCompletedEnrollmentV2(nextAnchor, next)
	if err != nil {
		t.Fatal("不能验历史v2节点", err)
	}
	opened, err := UnwrapEnvironmentKey(dr.Bytes(), EnvelopeContext{dg.AccountID, dg.AccountGeneration, dg.EnvironmentID, dg.KeyVersion, "device", dg.SubjectDeviceID, dg.GrantGeneration, dg.SubjectReceivingPublicKey}, packet)
	if err != nil || !bytes.Equal(opened, mustHex(t, v.EnvironmentKey)) {
		t.Fatal("D真实HPKE未绑定精确接收钥", err)
	}
	clear(opened)
	if len(verified.IssuerBindings()) != 3 {
		t.Fatal("未按环境取得三名既有管理签发者")
	}
}
