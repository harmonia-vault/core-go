package cryptox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
)

// RecoveryProof 只证明持有当前代恢复签名钥；不能自动变成管理设备。
type RecoveryProof struct {
	AccountID          string `json:"accountId"`
	AccountGeneration  string `json:"accountGeneration"`
	RecoveryGeneration string `json:"recoveryGeneration"`
	ChallengeID        string `json:"challengeId"`
	Nonce              string `json:"nonce"`
	ExpiresAt          string `json:"expiresAt"`
}

func (p RecoveryProof) SigningBytes() ([]byte, error) {
	for _, id := range []string{p.AccountID, p.ChallengeID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	for _, value := range []string{p.AccountGeneration, p.RecoveryGeneration, p.ExpiresAt} {
		if validDecimal(value, true) != nil {
			return nil, ErrInvalidWire
		}
	}
	if _, e := DecodeBase64(p.Nonce, 32, 32); e != nil {
		return nil, e
	}
	return canonical("harmonia/recovery-proof/v1", p.AccountID, p.AccountGeneration, p.RecoveryGeneration, p.ChallengeID, p.Nonce, p.ExpiresAt), nil
}
func SignRecoveryProof(p RecoveryProof, key ed25519.PrivateKey) (string, error) {
	b, e := p.SigningBytes()
	if e != nil {
		return "", e
	}
	return sign(key, b)
}
func VerifyRecoveryProof(p RecoveryProof, signature string, expectedRecoveryKey ed25519.PublicKey) error {
	b, e := p.SigningBytes()
	if e != nil {
		return e
	}
	return verify(expectedRecoveryKey, b, signature)
}

type RecoveryEnvelope struct {
	EnvironmentID string `json:"environmentId"`
	KeyVersion    string `json:"keyVersion"`
	Envelope      string `json:"envelope"`
}

func RecoveryEnvelopesHash(envelopes []RecoveryEnvelope) (string, error) {
	if len(envelopes) > 256 {
		return "", ErrInvalidWire
	}
	ordered := append([]RecoveryEnvelope(nil), envelopes...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].EnvironmentID < ordered[j].EnvironmentID })
	items := make([][]string, 0, len(ordered))
	for i, e := range ordered {
		if validID(e.EnvironmentID) != nil || validDecimal(e.KeyVersion, true) != nil || (i > 0 && ordered[i-1].EnvironmentID == e.EnvironmentID) {
			return "", ErrInvalidWire
		}
		if _, err := DecodeBase64(e.Envelope, 80, 80); err != nil {
			return "", err
		}
		items = append(items, []string{e.EnvironmentID, e.KeyVersion, e.Envelope})
	}
	return hashCanonical(items)
}

// Hash 包含新恢复钥重签的完整 manifest 签名，不能用对象序列化顺序决定。
func (r TrustRoot) Hash(accountID, accountGeneration string) (string, error) {
	b, e := r.SigningBytes(accountID, accountGeneration)
	if e != nil {
		return "", e
	}
	key, e := DecodeBase64(r.RecoverySigningPublicKey, 32, 32)
	if e != nil {
		return "", e
	}
	if e := VerifyTrustRoot(accountID, accountGeneration, r, key); e != nil {
		return "", e
	}
	var fields []string
	if e := json.Unmarshal(b, &fields); e != nil {
		return "", e
	}
	return hashCanonical(append(fields, r.Signature))
}

// 本公开轮换结构强制新可信根；不提供旧内部夹具的无 manifest 降级路径。
type RecoveryRotationProposal struct {
	IdempotencyKey                string             `json:"idempotencyKey"`
	NewRecoveryGeneration         string             `json:"newRecoveryGeneration"`
	NewRecoverySigningPublicKey   string             `json:"newRecoverySigningPublicKey"`
	NewRecoveryReceivingPublicKey string             `json:"newRecoveryReceivingPublicKey"`
	Envelopes                     []RecoveryEnvelope `json:"envelopes"`
	NewTrustRoot                  TrustRoot          `json:"newTrustRoot"`
}

type RecoveryRotationProof struct {
	AccountID                     string `json:"accountId"`
	AccountGeneration             string `json:"accountGeneration"`
	SessionHash                   string `json:"sessionHash"`
	RecoveryGeneration            string `json:"recoveryGeneration"`
	ChallengeID                   string `json:"challengeId"`
	Nonce                         string `json:"nonce"`
	ExpiresAt                     string `json:"expiresAt"`
	NewRecoveryGeneration         string `json:"newRecoveryGeneration"`
	NewRecoverySigningPublicKey   string `json:"newRecoverySigningPublicKey"`
	NewRecoveryReceivingPublicKey string `json:"newRecoveryReceivingPublicKey"`
	EnvelopesHash                 string `json:"envelopesHash"`
	TrustRootHash                 string `json:"trustRootHash"`
}

// priorRoot 必须已由本地恢复种子或确认过的公钥固定验证，不能盲信服务器根。
func NewRecoveryRotationProof(accountID, accountGeneration, sessionToken, challengeID, nonce, expiresAt string, p RecoveryRotationProposal, priorRoot TrustRoot) (RecoveryRotationProof, error) {
	if validID(p.IdempotencyKey) != nil {
		return RecoveryRotationProof{}, ErrInvalidWire
	}
	r := p.NewTrustRoot
	if r.RootDeviceID != priorRoot.RootDeviceID || r.RootSigningPublicKey != priorRoot.RootSigningPublicKey || r.RootReceivingPublicKey != priorRoot.RootReceivingPublicKey || r.RecoveryGeneration != p.NewRecoveryGeneration || r.RecoverySigningPublicKey != p.NewRecoverySigningPublicKey || r.RecoveryReceivingPublicKey != p.NewRecoveryReceivingPublicKey || r.RecoverySigningPublicKey == priorRoot.RecoverySigningPublicKey || r.RecoveryReceivingPublicKey == priorRoot.RecoveryReceivingPublicKey {
		return RecoveryRotationProof{}, ErrInvalidWire
	}
	rootHash, e := r.Hash(accountID, accountGeneration)
	if e != nil {
		return RecoveryRotationProof{}, e
	}
	envHash, e := RecoveryEnvelopesHash(p.Envelopes)
	if e != nil {
		return RecoveryRotationProof{}, e
	}
	sessionHash := sha256.Sum256([]byte(sessionToken))
	proof := RecoveryRotationProof{accountID, accountGeneration, hex.EncodeToString(sessionHash[:]), priorRoot.RecoveryGeneration, challengeID, nonce, expiresAt, p.NewRecoveryGeneration, p.NewRecoverySigningPublicKey, p.NewRecoveryReceivingPublicKey, envHash, rootHash}
	if _, e := proof.SigningBytes(); e != nil {
		return RecoveryRotationProof{}, e
	}
	return proof, nil
}

func (p RecoveryRotationProof) SigningBytes() ([]byte, error) {
	for _, id := range []string{p.AccountID, p.ChallengeID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	for _, value := range []string{p.AccountGeneration, p.RecoveryGeneration, p.NewRecoveryGeneration, p.ExpiresAt} {
		if validDecimal(value, true) != nil {
			return nil, ErrInvalidWire
		}
	}
	old, _ := strconv.ParseUint(p.RecoveryGeneration, 10, 64)
	next, _ := strconv.ParseUint(p.NewRecoveryGeneration, 10, 64)
	if old == math.MaxUint64 || next != old+1 {
		return nil, ErrInvalidWire
	}
	if !tokenHashPattern.MatchString(p.SessionHash) || !tokenHashPattern.MatchString(p.EnvelopesHash) || !tokenHashPattern.MatchString(p.TrustRootHash) || validatePublicPair(p.NewRecoverySigningPublicKey, p.NewRecoveryReceivingPublicKey) != nil {
		return nil, ErrInvalidWire
	}
	if _, e := DecodeBase64(p.Nonce, 32, 32); e != nil {
		return nil, e
	}
	return canonical("harmonia/recovery-rotation/v1", p.AccountID, p.AccountGeneration, p.SessionHash, p.RecoveryGeneration, p.ChallengeID, p.Nonce, p.ExpiresAt, p.NewRecoveryGeneration, p.NewRecoverySigningPublicKey, p.NewRecoveryReceivingPublicKey, p.EnvelopesHash, p.TrustRootHash), nil
}
func SignRecoveryRotationProof(p RecoveryRotationProof, key ed25519.PrivateKey) (string, error) {
	b, e := p.SigningBytes()
	if e != nil {
		return "", e
	}
	if len(key) != ed25519.PrivateKeySize || p.NewRecoverySigningPublicKey != EncodeBase64(key.Public().(ed25519.PublicKey)) {
		return "", ErrInvalidWire
	}
	return sign(key, b)
}
func VerifyRecoveryRotationProof(p RecoveryRotationProof, signature string, expectedNewRecoveryKey ed25519.PublicKey) error {
	b, e := p.SigningBytes()
	if e != nil {
		return e
	}
	if p.NewRecoverySigningPublicKey != EncodeBase64(expectedNewRecoveryKey) {
		return ErrInvalidSignature
	}
	return verify(expectedNewRecoveryKey, b, signature)
}
