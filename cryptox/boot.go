package cryptox

import "crypto/ed25519"

// DeviceBootProof 让重启后的既有可信设备用软件签名钥重新取得绑定会话。
// 校验签名不能代替服务器核对当前设备、公钥、代际、有效授权和单次挑战。
type DeviceBootProof struct {
	AccountID          string `json:"accountId"`
	AccountGeneration  string `json:"accountGeneration"`
	DeviceID           string `json:"deviceId"`
	SigningPublicKey   string `json:"signingPublicKey"`
	ReceivingPublicKey string `json:"receivingPublicKey"`
	ChallengeID        string `json:"challengeId"`
	Nonce              string `json:"nonce"`
	ExpiresAt          string `json:"expiresAt"`
}

// NewDeviceBootProof 必须传入本地已知的账号、设备和两把独立公钥。
// 不对服务器返回的任意 signingPayload 盲签。
func NewDeviceBootProof(accountID, accountGeneration, deviceID string, signingPublicKey, receivingPublicKey []byte, challengeID, nonce, expiresAt string) (DeviceBootProof, error) {
	p := DeviceBootProof{accountID, accountGeneration, deviceID, EncodeBase64(signingPublicKey), EncodeBase64(receivingPublicKey), challengeID, nonce, expiresAt}
	if _, err := p.SigningBytes(); err != nil {
		return DeviceBootProof{}, err
	}
	return p, nil
}

func (p DeviceBootProof) SigningBytes() ([]byte, error) {
	for _, id := range []string{p.AccountID, p.DeviceID, p.ChallengeID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	if validDecimal(p.AccountGeneration, true) != nil || validDecimal(p.ExpiresAt, true) != nil {
		return nil, ErrInvalidWire
	}
	for _, key := range []string{p.SigningPublicKey, p.ReceivingPublicKey, p.Nonce} {
		if _, err := DecodeBase64(key, 32, 32); err != nil {
			return nil, err
		}
	}
	if p.SigningPublicKey == p.ReceivingPublicKey {
		return nil, ErrInvalidWire
	}
	return canonical("harmonia/device-boot/v1", p.AccountID, p.AccountGeneration, p.DeviceID, p.SigningPublicKey, p.ReceivingPublicKey, p.ChallengeID, p.Nonce, p.ExpiresAt), nil
}

func SignDeviceBootProof(p DeviceBootProof, key ed25519.PrivateKey) (string, error) {
	b, err := p.SigningBytes()
	if err != nil {
		return "", err
	}
	if len(key) != ed25519.PrivateKeySize || p.SigningPublicKey != EncodeBase64(key.Public().(ed25519.PublicKey)) {
		return "", ErrInvalidWire
	}
	return sign(key, b)
}

func VerifyDeviceBootProof(p DeviceBootProof, signature string, trustedDeviceKey ed25519.PublicKey) error {
	b, err := p.SigningBytes()
	if err != nil {
		return err
	}
	if p.SigningPublicKey != EncodeBase64(trustedDeviceKey) {
		return ErrInvalidSignature
	}
	return verify(trustedDeviceKey, b, signature)
}
