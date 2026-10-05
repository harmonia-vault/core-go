package cryptox

import (
	"crypto/ed25519"
	"encoding/json"
	"sort"
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
