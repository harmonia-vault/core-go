package cryptox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

const EnrollmentPairingProfile = "boringssl-spake2-edwards25519-draft02-v1"

// SignedGrantWire 使用 HTTP 中的嵌套授权对象，既有 SignedGrant 的布局不变。
type SignedGrantWire struct {
	Grant     Grant  `json:"grant"`
	Signature string `json:"signature"`
}

func GrantToWire(g SignedGrant) SignedGrantWire    { return SignedGrantWire{g.Grant, g.Signature} }
func (g SignedGrantWire) SignedGrant() SignedGrant { return SignedGrant{g.Grant, g.Signature} }

// TrustRoot 将精确根设备身份与本代恢复钥绑定；恢复轮换须原子重签根声明。
type TrustRoot struct {
	RootDeviceID               string `json:"rootDeviceId"`
	RootSigningPublicKey       string `json:"rootSigningPublicKey"`
	RootReceivingPublicKey     string `json:"rootReceivingPublicKey"`
	RecoveryGeneration         string `json:"recoveryGeneration"`
	RecoverySigningPublicKey   string `json:"recoverySigningPublicKey"`
	RecoveryReceivingPublicKey string `json:"recoveryReceivingPublicKey"`
	Signature                  string `json:"signature"`
}

func validatePublicPair(signing, receiving string) error {
	for _, key := range []string{signing, receiving} {
		if _, err := DecodeBase64(key, 32, 32); err != nil {
			return err
		}
	}
	if signing == receiving {
		return ErrInvalidWire
	}
	return nil
}

func (r TrustRoot) SigningBytes(accountID, accountGeneration string) ([]byte, error) {
	if validID(accountID) != nil || validID(r.RootDeviceID) != nil || validDecimal(accountGeneration, true) != nil || validDecimal(r.RecoveryGeneration, true) != nil {
		return nil, ErrInvalidWire
	}
	if validatePublicPair(r.RootSigningPublicKey, r.RootReceivingPublicKey) != nil || validatePublicPair(r.RecoverySigningPublicKey, r.RecoveryReceivingPublicKey) != nil {
		return nil, ErrInvalidWire
	}
	if r.RootSigningPublicKey == r.RecoverySigningPublicKey {
		return nil, ErrInvalidWire
	}
	return canonical("harmonia/trust-root/v1", accountID, accountGeneration, r.RootDeviceID, r.RootSigningPublicKey, r.RootReceivingPublicKey, r.RecoveryGeneration, r.RecoverySigningPublicKey, r.RecoveryReceivingPublicKey), nil
}

func SignTrustRoot(accountID, accountGeneration string, r TrustRoot, key ed25519.PrivateKey) (TrustRoot, error) {
	b, err := r.SigningBytes(accountID, accountGeneration)
	if err != nil {
		return TrustRoot{}, err
	}
	if len(key) != ed25519.PrivateKeySize || r.RecoverySigningPublicKey != EncodeBase64(key.Public().(ed25519.PublicKey)) {
		return TrustRoot{}, ErrInvalidWire
	}
	r.Signature, err = sign(key, b)
	return r, err
}

// expectedRecoveryKey 必须来自已确认配对或本地恢复种子，不能只信服务器声明。
func VerifyTrustRoot(accountID, accountGeneration string, r TrustRoot, expectedRecoveryKey ed25519.PublicKey) error {
	b, err := r.SigningBytes(accountID, accountGeneration)
	if err != nil {
		return err
	}
	if r.RecoverySigningPublicKey != EncodeBase64(expectedRecoveryKey) {
		return ErrInvalidSignature
	}
	return verify(expectedRecoveryKey, b, r.Signature)
}

type InitializationDevice struct {
	ID                 string `json:"id"`
	SigningPublicKey   string `json:"signingPublicKey"`
	ReceivingPublicKey string `json:"receivingPublicKey"`
}

type InitializationEnvironment struct {
	EnvironmentID    string          `json:"environmentId"`
	KeyVersion       string          `json:"keyVersion"`
	RecoveryEnvelope string          `json:"recoveryEnvelope"`
	Grant            SignedGrantWire `json:"grant"`
}

// InitializationProposal 明确包含全部初始封套和已签自授权，不包含明文或恢复种子。
type InitializationProposal struct {
	IdempotencyKey             string                      `json:"idempotencyKey"`
	Device                     InitializationDevice        `json:"device"`
	RecoveryGeneration         string                      `json:"recoveryGeneration"`
	RecoverySigningPublicKey   string                      `json:"recoverySigningPublicKey"`
	RecoveryReceivingPublicKey string                      `json:"recoveryReceivingPublicKey"`
	TrustRootSignature         string                      `json:"trustRootSignature"`
	Environments               []InitializationEnvironment `json:"environments"`
}

func hashCanonical(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func (p InitializationProposal) Hash(accountID, accountGeneration string) (string, error) {
	if validID(p.IdempotencyKey) != nil {
		return "", ErrInvalidWire
	}
	r := TrustRoot{p.Device.ID, p.Device.SigningPublicKey, p.Device.ReceivingPublicKey, p.RecoveryGeneration, p.RecoverySigningPublicKey, p.RecoveryReceivingPublicKey, p.TrustRootSignature}
	if _, err := r.SigningBytes(accountID, accountGeneration); err != nil {
		return "", err
	}
	if _, err := DecodeBase64(p.TrustRootSignature, 64, 64); err != nil {
		return "", err
	}
	if p.RecoveryGeneration != "1" || len(p.Environments) < 1 || len(p.Environments) > 16 {
		return "", ErrInvalidWire
	}
	recoveryKey, _ := DecodeBase64(p.RecoverySigningPublicKey, 32, 32)
	if err := VerifyTrustRoot(accountID, accountGeneration, r, recoveryKey); err != nil {
		return "", err
	}
	envs := append([]InitializationEnvironment(nil), p.Environments...)
	sort.Slice(envs, func(i, j int) bool { return envs[i].EnvironmentID < envs[j].EnvironmentID })
	items := make([][]string, 0, len(envs))
	for i, e := range envs {
		if validID(e.EnvironmentID) != nil || e.KeyVersion != "1" || (i > 0 && envs[i-1].EnvironmentID == e.EnvironmentID) {
			return "", ErrInvalidWire
		}
		if _, err := DecodeBase64(e.RecoveryEnvelope, 80, 80); err != nil {
			return "", err
		}
		g := e.Grant.Grant
		if g.AccountID != accountID || g.AccountGeneration != accountGeneration || g.EnvironmentID != e.EnvironmentID || g.KeyVersion != e.KeyVersion || g.IssuerDeviceID != p.Device.ID || g.SubjectDeviceID != p.Device.ID || g.SubjectSigningPublicKey != p.Device.SigningPublicKey || g.SubjectReceivingPublicKey != p.Device.ReceivingPublicKey || g.Role != "admin" || g.GrantGeneration != "1" || g.ExpiresAt != "0" {
			return "", ErrInvalidWire
		}
		encoded, err := g.SigningBytes()
		if err != nil {
			return "", err
		}
		if _, err := DecodeBase64(e.Grant.Signature, 64, 64); err != nil {
			return "", err
		}
		rootKey, _ := DecodeBase64(p.Device.SigningPublicKey, 32, 32)
		if err := VerifyGrant(e.Grant.SignedGrant(), rootKey); err != nil {
			return "", err
		}
		items = append(items, []string{e.EnvironmentID, e.KeyVersion, e.RecoveryEnvelope, EncodeBase64(encoded), e.Grant.Signature})
	}
	return hashCanonical([]any{"harmonia/vault-initialization-proposal/v1", p.IdempotencyKey, p.Device.ID, p.Device.SigningPublicKey, p.Device.ReceivingPublicKey, p.RecoveryGeneration, p.RecoverySigningPublicKey, p.RecoveryReceivingPublicKey, p.TrustRootSignature, items})
}

type InitializationProof struct {
	AccountID         string `json:"accountId"`
	AccountGeneration string `json:"accountGeneration"`
	LoginTokenHash    string `json:"loginTokenHash"`
	ChallengeID       string `json:"challengeId"`
	Nonce             string `json:"nonce"`
	ExpiresAt         string `json:"expiresAt"`
	ProposalHash      string `json:"proposalHash"`
}

func NewInitializationProof(accountID, accountGeneration, loginToken, challengeID, nonce, expiresAt, proposalHash string) (InitializationProof, error) {
	h := sha256.Sum256([]byte(loginToken))
	p := InitializationProof{accountID, accountGeneration, hex.EncodeToString(h[:]), challengeID, nonce, expiresAt, proposalHash}
	if _, err := p.SigningBytes(); err != nil {
		return InitializationProof{}, err
	}
	return p, nil
}

func (p InitializationProof) SigningBytes() ([]byte, error) {
	for _, id := range []string{p.AccountID, p.ChallengeID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	if validDecimal(p.AccountGeneration, true) != nil || validDecimal(p.ExpiresAt, true) != nil || !tokenHashPattern.MatchString(p.LoginTokenHash) || !tokenHashPattern.MatchString(p.ProposalHash) {
		return nil, ErrInvalidWire
	}
	if _, err := DecodeBase64(p.Nonce, 32, 32); err != nil {
		return nil, err
	}
	return canonical("harmonia/vault-initialize/v1", p.AccountID, p.AccountGeneration, p.LoginTokenHash, p.ChallengeID, p.Nonce, p.ExpiresAt, p.ProposalHash), nil
}

func SignInitializationProof(p InitializationProof, key ed25519.PrivateKey) (string, error) {
	b, err := p.SigningBytes()
	if err != nil {
		return "", err
	}
	return sign(key, b)
}
func VerifyInitializationProof(p InitializationProof, signature string, key ed25519.PublicKey) error {
	b, err := p.SigningBytes()
	if err != nil {
		return err
	}
	return verify(key, b, signature)
}

func EnrollmentGrantsHash(grants []SignedGrantWire) (string, error) {
	if len(grants) < 1 || len(grants) > 256 {
		return "", ErrInvalidWire
	}
	ordered := append([]SignedGrantWire(nil), grants...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Grant.EnvironmentID < ordered[j].Grant.EnvironmentID })
	items := make([][]string, 0, len(ordered))
	for i, g := range ordered {
		if i > 0 && ordered[i-1].Grant.EnvironmentID == g.Grant.EnvironmentID {
			return "", ErrInvalidWire
		}
		encoded, err := g.Grant.SigningBytes()
		if err != nil {
			return "", err
		}
		if _, err := DecodeBase64(g.Signature, 64, 64); err != nil {
			return "", err
		}
		items = append(items, []string{g.Grant.EnvironmentID, EncodeBase64(encoded), g.Signature})
	}
	return hashCanonical(items)
}

// EnrollmentCertificate 在手机显式批准之后双签，绑定已确认 PAKE 的 transcript。
type EnrollmentCertificate struct {
	PairingProfile              string `json:"pairingProfile"`
	AccountID                   string `json:"accountId"`
	AccountGeneration           string `json:"accountGeneration"`
	SessionID                   string `json:"sessionId"`
	Nonce                       string `json:"nonce"`
	ExpiresAt                   string `json:"expiresAt"`
	InitiatorDeviceID           string `json:"initiatorDeviceId"`
	InitiatorSigningPublicKey   string `json:"initiatorSigningPublicKey"`
	InitiatorReceivingPublicKey string `json:"initiatorReceivingPublicKey"`
	ApproverDeviceID            string `json:"approverDeviceId"`
	ApproverSigningPublicKey    string `json:"approverSigningPublicKey"`
	ApproverReceivingPublicKey  string `json:"approverReceivingPublicKey"`
	TranscriptHash              string `json:"transcriptHash"`
	GrantsHash                  string `json:"grantsHash"`
}

func (c EnrollmentCertificate) fields() ([]string, error) {
	for _, id := range []string{c.AccountID, c.SessionID, c.InitiatorDeviceID, c.ApproverDeviceID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	if c.PairingProfile != EnrollmentPairingProfile || c.InitiatorDeviceID == c.ApproverDeviceID || validDecimal(c.AccountGeneration, true) != nil || validDecimal(c.ExpiresAt, true) != nil || !tokenHashPattern.MatchString(c.TranscriptHash) || !tokenHashPattern.MatchString(c.GrantsHash) {
		return nil, ErrInvalidWire
	}
	if validatePublicPair(c.InitiatorSigningPublicKey, c.InitiatorReceivingPublicKey) != nil || validatePublicPair(c.ApproverSigningPublicKey, c.ApproverReceivingPublicKey) != nil || c.InitiatorSigningPublicKey == c.ApproverSigningPublicKey {
		return nil, ErrInvalidWire
	}
	if _, err := DecodeBase64(c.Nonce, 32, 32); err != nil {
		return nil, err
	}
	return []string{c.PairingProfile, c.AccountID, c.AccountGeneration, c.SessionID, c.Nonce, c.ExpiresAt, c.InitiatorDeviceID, c.InitiatorSigningPublicKey, c.InitiatorReceivingPublicKey, c.ApproverDeviceID, c.ApproverSigningPublicKey, c.ApproverReceivingPublicKey, c.TranscriptHash, c.GrantsHash}, nil
}

// VerifyEnrollmentGrants 验证证书绑定的每个授权；服务器还须检查逐环境当前管理权。
func VerifyEnrollmentGrants(c EnrollmentCertificate, grants []SignedGrantWire, expectedApproverKey ed25519.PublicKey) error {
	if _, err := c.fields(); err != nil {
		return err
	}
	if c.ApproverSigningPublicKey != EncodeBase64(expectedApproverKey) {
		return ErrInvalidSignature
	}
	hash, err := EnrollmentGrantsHash(grants)
	if err != nil {
		return err
	}
	if hash != c.GrantsHash || len(grants) == 0 {
		return ErrInvalidWire
	}
	for _, g := range grants {
		v := g.Grant
		if v.AccountID != c.AccountID || v.AccountGeneration != c.AccountGeneration || v.IssuerDeviceID != c.ApproverDeviceID || v.SubjectDeviceID != c.InitiatorDeviceID || v.SubjectSigningPublicKey != c.InitiatorSigningPublicKey || v.SubjectReceivingPublicKey != c.InitiatorReceivingPublicKey || v.Role == "none" {
			return ErrInvalidWire
		}
		if err := VerifyGrant(g.SignedGrant(), expectedApproverKey); err != nil {
			return err
		}
	}
	return nil
}
