package cryptox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func readVector(t *testing.T, name string, value any) {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, value); e != nil {
		t.Fatal(e)
	}
}
func cloneJSON[T any](t *testing.T, value T) T {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	var out T
	if e = json.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	return out
}

type initializationVector struct {
	RootSeed        string `json:"syntheticRootSigningSeedHex"`
	RootReceiving   string `json:"syntheticRootReceivingPrivateHex"`
	RecoverySeed    string `json:"syntheticRecoverySeedHex"`
	LoginToken      string `json:"syntheticLoginToken"`
	EnvironmentKeys []struct {
		EnvironmentID string `json:"environmentId"`
		KeyHex        string `json:"keyHex"`
	} `json:"syntheticEnvironmentKeys"`
	Root              TrustRoot              `json:"trustRoot"`
	RootSigningHex    string                 `json:"trustRootSigningHex"`
	Proposal          InitializationProposal `json:"proposal"`
	Proof             InitializationProof    `json:"proof"`
	ProofSigningHex   string                 `json:"proofSigningHex"`
	RootSignature     string                 `json:"rootSignature"`
	RecoverySignature string                 `json:"recoverySignature"`
}

func TestInitializationCrossLanguageProofAndRealHPKE(t *testing.T) {
	var v initializationVector
	readVector(t, "vault-initialization-v1.json", &v)
	root := ed25519.NewKeyFromSeed(mustHex(t, v.RootSeed))
	pub := root.Public().(ed25519.PublicKey)
	recovery, e := DeriveRecoveryKeys(mustHex(t, v.RecoverySeed), v.Proof.AccountID, v.Proof.AccountGeneration, v.Root.RecoveryGeneration)
	if e != nil {
		t.Fatal(e)
	}
	b, e := v.Root.SigningBytes(v.Proof.AccountID, v.Proof.AccountGeneration)
	if e != nil || hex.EncodeToString(b) != v.RootSigningHex {
		t.Fatal("根声明确定编码不同")
	}
	if e = VerifyTrustRoot(v.Proof.AccountID, v.Proof.AccountGeneration, v.Root, recovery.SigningPublic); e != nil {
		t.Fatal(e)
	}
	r, e := SignTrustRoot(v.Proof.AccountID, v.Proof.AccountGeneration, v.Root, recovery.SigningPrivate)
	if e != nil || r != v.Root {
		t.Fatal("根声明标准签名不同")
	}
	h, e := v.Proposal.Hash(v.Proof.AccountID, v.Proof.AccountGeneration)
	if e != nil || h != v.Proof.ProposalHash {
		t.Fatalf("初始化 proposal hash 不同: %v", e)
	}
	p, e := NewInitializationProof(v.Proof.AccountID, v.Proof.AccountGeneration, v.LoginToken, v.Proof.ChallengeID, v.Proof.Nonce, v.Proof.ExpiresAt, h)
	if e != nil || p != v.Proof {
		t.Fatal("初始化证明本地构造不同")
	}
	b, e = p.SigningBytes()
	if e != nil || hex.EncodeToString(b) != v.ProofSigningHex {
		t.Fatal("初始化证明确定编码不同")
	}
	for _, pair := range []struct {
		key ed25519.PrivateKey
		pub ed25519.PublicKey
		sig string
	}{{root, pub, v.RootSignature}, {recovery.SigningPrivate, recovery.SigningPublic, v.RecoverySignature}} {
		sig, e := SignInitializationProof(p, pair.key)
		if e != nil || sig != pair.sig {
			t.Fatal("双证明标准签名不同")
		}
		if e = VerifyInitializationProof(p, pair.sig, pair.pub); e != nil {
			t.Fatal(e)
		}
	}
	if VerifyInitializationProof(p, v.RootSignature, recovery.SigningPublic) == nil || VerifyInitializationProof(p, v.RecoverySignature, pub) == nil {
		t.Fatal("根设备与恢复签名互换被接受")
	}
	keyMap := map[string][]byte{}
	for _, k := range v.EnvironmentKeys {
		keyMap[k.EnvironmentID] = mustHex(t, k.KeyHex)
	}
	for _, env := range v.Proposal.Environments {
		if e := VerifyGrant(env.Grant.SignedGrant(), pub); e != nil {
			t.Fatal(e)
		}
		c := EnvelopeContext{p.AccountID, p.AccountGeneration, env.EnvironmentID, env.KeyVersion, "device", v.Proposal.Device.ID, env.Grant.Grant.GrantGeneration, v.Proposal.Device.ReceivingPublicKey}
		packet, e := DecodeBase64(env.Grant.Grant.Envelope, 80, 80)
		if e != nil {
			t.Fatal(e)
		}
		key, e := UnwrapEnvironmentKey(mustHex(t, v.RootReceiving), c, packet)
		if e != nil || !bytes.Equal(key, keyMap[env.EnvironmentID]) {
			t.Fatalf("初始设备真实 HPKE 封套不匹配: %v", e)
		}
		c.RecipientType = "recovery"
		c.RecipientID = p.AccountID
		c.RecipientGeneration = v.Root.RecoveryGeneration
		c.RecipientPublicKey = v.Root.RecoveryReceivingPublicKey
		packet, e = DecodeBase64(env.RecoveryEnvelope, 80, 80)
		if e != nil {
			t.Fatal(e)
		}
		key, e = UnwrapEnvironmentKey(recovery.ReceivingPrivate, c, packet)
		if e != nil || !bytes.Equal(key, keyMap[env.EnvironmentID]) {
			t.Fatalf("恢复真实 HPKE 封套不匹配: %v", e)
		}
	}
}

func TestInitializationEveryBindingAndOrdering(t *testing.T) {
	var v initializationVector
	readVector(t, "vault-initialization-v1.json", &v)
	recovery, e := DeriveRecoveryKeys(mustHex(t, v.RecoverySeed), v.Proof.AccountID, v.Proof.AccountGeneration, v.Root.RecoveryGeneration)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < reflect.TypeFor[TrustRoot]().NumField(); i++ {
		bad := v.Root
		f := reflect.ValueOf(&bad).Elem().Field(i)
		switch i {
		case 0:
			f.SetString("root-other")
		case 3:
			f.SetString("2")
		case 6:
			f.SetString(EncodeBase64(fixtureBytes(64, 20)))
		default:
			f.SetString(EncodeBase64(fixtureBytes(32, 200)))
		}
		if VerifyTrustRoot(v.Proof.AccountID, v.Proof.AccountGeneration, bad, recovery.SigningPublic) == nil {
			t.Fatalf("根声明未绑定字段 %d", i)
		}
	}
	if VerifyTrustRoot("account-other", v.Proof.AccountGeneration, v.Root, recovery.SigningPublic) == nil || VerifyTrustRoot(v.Proof.AccountID, "2", v.Root, recovery.SigningPublic) == nil {
		t.Fatal("根声明未绑定账号代际")
	}
	for i := 0; i < reflect.TypeFor[InitializationProof]().NumField(); i++ {
		bad := v.Proof
		f := reflect.ValueOf(&bad).Elem().Field(i)
		switch i {
		case 1:
			f.SetString("2")
		case 2, 6:
			f.SetString(strings.Repeat("1", 64))
		case 4:
			f.SetString(EncodeBase64(fixtureBytes(32, 200)))
		case 5:
			f.SetString("4102444801")
		default:
			f.SetString(f.String() + "-other")
		}
		if VerifyInitializationProof(bad, v.RecoverySignature, recovery.SigningPublic) == nil {
			t.Fatalf("初始化证明未绑定字段 %d", i)
		}
	}
	p := cloneJSON(t, v.Proposal)
	p.Environments[0], p.Environments[1] = p.Environments[1], p.Environments[0]
	h, e := p.Hash(v.Proof.AccountID, v.Proof.AccountGeneration)
	if e != nil || h != v.Proof.ProposalHash {
		t.Fatal("输入环境顺序改变初始化hash")
	}
	if p.Environments[0].EnvironmentID == v.Proposal.Environments[0].EnvironmentID {
		t.Fatal("测试顺序未变化")
	}
	p = cloneJSON(t, v.Proposal)
	p.Environments = append(p.Environments, p.Environments[0])
	if _, e = p.Hash(v.Proof.AccountID, v.Proof.AccountGeneration); e == nil {
		t.Fatal("重复初始环境被接受")
	}
	mutations := []func(*InitializationProposal){
		func(p *InitializationProposal) { p.IdempotencyKey += "-other" },
		func(p *InitializationProposal) { p.Device.ID += "-other" },
		func(p *InitializationProposal) { p.Device.SigningPublicKey = EncodeBase64(fixtureBytes(32, 200)) },
		func(p *InitializationProposal) { p.Device.ReceivingPublicKey = EncodeBase64(fixtureBytes(32, 201)) },
		func(p *InitializationProposal) { p.RecoveryGeneration = "2" },
		func(p *InitializationProposal) { p.RecoverySigningPublicKey = EncodeBase64(fixtureBytes(32, 202)) },
		func(p *InitializationProposal) { p.RecoveryReceivingPublicKey = EncodeBase64(fixtureBytes(32, 203)) },
		func(p *InitializationProposal) { p.TrustRootSignature = EncodeBase64(fixtureBytes(64, 20)) },
		func(p *InitializationProposal) { p.Environments[0].EnvironmentID += "-other" },
		func(p *InitializationProposal) { p.Environments[0].KeyVersion = "2" },
		func(p *InitializationProposal) {
			p.Environments[0].RecoveryEnvelope = EncodeBase64(fixtureBytes(80, 204))
		},
		func(p *InitializationProposal) {
			p.Environments[0].Grant.Grant.Envelope = EncodeBase64(fixtureBytes(80, 205))
		},
		func(p *InitializationProposal) {
			p.Environments[0].Grant.Signature = EncodeBase64(fixtureBytes(64, 21))
		},
	}
	for i, mutate := range mutations {
		p := cloneJSON(t, v.Proposal)
		mutate(&p)
		h, e := p.Hash(v.Proof.AccountID, v.Proof.AccountGeneration)
		if e == nil && h == v.Proof.ProposalHash {
			t.Fatalf("初始化 proposal 未绑定字段 %d", i)
		}
	}
}

type enrollmentVector struct {
	Certificate        EnrollmentCertificate `json:"certificate"`
	SigningHex         string                `json:"certificateSigningHex"`
	ApproverSignature  string                `json:"approverSignature"`
	InitiatorSignature string                `json:"initiatorSignature"`
	ApproverSeed       string                `json:"syntheticApproverSigningSeedHex"`
	InitiatorSeed      string                `json:"syntheticInitiatorSigningSeedHex"`
	InitiatorReceiving string                `json:"syntheticInitiatorReceivingPrivateHex"`
	Grants             []SignedGrantWire     `json:"grants"`
	EnvironmentKeys    []struct {
		EnvironmentID string `json:"environmentId"`
		KeyHex        string `json:"keyHex"`
	} `json:"syntheticEnvironmentKeys"`
}

func TestEnrollmentCrossLanguageDualProofAndGrants(t *testing.T) {
	var v enrollmentVector
	readVector(t, "device-enrollment-v1.json", &v)
	a := ed25519.NewKeyFromSeed(mustHex(t, v.ApproverSeed))
	b := ed25519.NewKeyFromSeed(mustHex(t, v.InitiatorSeed))
	encoded, e := v.Certificate.SigningBytes()
	if e != nil || hex.EncodeToString(encoded) != v.SigningHex {
		t.Fatalf("入网确定编码不同: %v", e)
	}
	for _, p := range []struct {
		key ed25519.PrivateKey
		sig string
	}{{a, v.ApproverSignature}, {b, v.InitiatorSignature}} {
		s, e := SignEnrollmentCertificate(v.Certificate, p.key)
		if e != nil || s != p.sig {
			t.Fatal("入网双签名不同")
		}
		if e = VerifyEnrollmentCertificate(v.Certificate, p.sig, p.key.Public().(ed25519.PublicKey)); e != nil {
			t.Fatal(e)
		}
	}
	if VerifyEnrollmentCertificate(v.Certificate, v.ApproverSignature, b.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("发起者与管理者证明互换被接受")
	}
	if e := VerifyEnrollmentGrants(v.Certificate, v.Grants, a.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal(e)
	}
	reversed := append([]SignedGrantWire(nil), v.Grants...)
	reversed[0], reversed[1] = reversed[1], reversed[0]
	h, e := EnrollmentGrantsHash(reversed)
	if e != nil || h != v.Certificate.GrantsHash {
		t.Fatal("授权输入顺序改变hash")
	}
	keyMap := map[string][]byte{}
	for _, k := range v.EnvironmentKeys {
		keyMap[k.EnvironmentID] = mustHex(t, k.KeyHex)
	}
	for _, g := range v.Grants {
		c := EnvelopeContext{g.Grant.AccountID, g.Grant.AccountGeneration, g.Grant.EnvironmentID, g.Grant.KeyVersion, "device", g.Grant.SubjectDeviceID, g.Grant.GrantGeneration, g.Grant.SubjectReceivingPublicKey}
		packet, e := DecodeBase64(g.Grant.Envelope, 80, 80)
		if e != nil {
			t.Fatal(e)
		}
		k, e := UnwrapEnvironmentKey(mustHex(t, v.InitiatorReceiving), c, packet)
		if e != nil || !bytes.Equal(k, keyMap[g.Grant.EnvironmentID]) {
			t.Fatalf("新设备真实HPKE封套不同: %v", e)
		}
	}
	for i := 0; i < reflect.TypeFor[EnrollmentCertificate]().NumField(); i++ {
		bad := v.Certificate
		f := reflect.ValueOf(&bad).Elem().Field(i)
		switch i {
		case 0:
			f.SetString("unsupported-profile")
		case 2:
			f.SetString("2")
		case 4, 7, 8, 10, 11:
			f.SetString(EncodeBase64(fixtureBytes(32, 200)))
		case 5:
			f.SetString("4102444801")
		case 12, 13:
			f.SetString(strings.Repeat("1", 64))
		default:
			f.SetString(f.String() + "-other")
		}
		if VerifyEnrollmentCertificate(bad, v.ApproverSignature, a.Public().(ed25519.PublicKey)) == nil {
			t.Fatalf("入网证书未绑定字段 %d", i)
		}
	}
	duplicate := append(v.Grants, v.Grants[0])
	if _, e := EnrollmentGrantsHash(duplicate); e == nil {
		t.Fatal("接受重复授权环境")
	}
	badGrants := cloneJSON(t, v.Grants)
	badGrants[0].Grant.Role = "admin"
	if VerifyEnrollmentGrants(v.Certificate, badGrants, a.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("授权role替换被接受")
	}
}
