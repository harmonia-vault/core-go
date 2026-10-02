package cryptox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

var tokenHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// DeviceSessionProof 证明登录会话与既有可信设备签名钥的绑定。
// 签名成功不等于可信入网；服务器必须先核对该设备的当前授权和代际。
type DeviceSessionProof struct {
	AccountID         string `json:"accountId"`
	AccountGeneration string `json:"accountGeneration"`
	DeviceID          string `json:"deviceId"`
	LoginTokenHash    string `json:"loginTokenHash"`
	ChallengeID       string `json:"challengeId"`
	Nonce             string `json:"nonce"`
	ExpiresAt         string `json:"expiresAt"`
}

// NewDeviceSessionProof 使用客户端已知账号、设备和登录 token 构造证明。
// 调用方不能直接对服务器提供的任意 signingPayload 数组盲签。
func NewDeviceSessionProof(accountID, accountGeneration, deviceID, loginToken, challengeID, nonce, expiresAt string) (DeviceSessionProof, error) {
	tokenHash := sha256.Sum256([]byte(loginToken))
	p := DeviceSessionProof{accountID, accountGeneration, deviceID, hex.EncodeToString(tokenHash[:]), challengeID, nonce, expiresAt}
	if _, err := p.SigningBytes(); err != nil {
		return DeviceSessionProof{}, err
	}
	return p, nil
}

func (p DeviceSessionProof) SigningBytes() ([]byte, error) {
	for _, id := range []string{p.AccountID, p.DeviceID, p.ChallengeID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	if validDecimal(p.AccountGeneration, true) != nil || validDecimal(p.ExpiresAt, true) != nil || !tokenHashPattern.MatchString(p.LoginTokenHash) {
		return nil, ErrInvalidWire
	}
	if _, err := DecodeBase64(p.Nonce, 32, 32); err != nil {
		return nil, err
	}
	return canonical("harmonia/device-session/v1", p.AccountID, p.AccountGeneration, p.DeviceID, p.LoginTokenHash, p.ChallengeID, p.Nonce, p.ExpiresAt), nil
}

func SignDeviceSessionProof(p DeviceSessionProof, key ed25519.PrivateKey) (string, error) {
	b, err := p.SigningBytes()
	if err != nil {
		return "", err
	}
	return sign(key, b)
}

func VerifyDeviceSessionProof(p DeviceSessionProof, signature string, trustedDeviceKey ed25519.PublicKey) error {
	b, err := p.SigningBytes()
	if err != nil {
		return err
	}
	return verify(trustedDeviceKey, b, signature)
}
