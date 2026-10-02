package cryptox

import "crypto/ed25519"

// PairingRelay 只允许中继公共消息和确认值；不包含或序列化秘密短码。
// trustedSideKey 必须对应当前服务器/客户端冻结的精确角色公钥。
type PairingRelay struct {
	AccountID         string `json:"accountId"`
	AccountGeneration string `json:"accountGeneration"`
	SessionID         string `json:"sessionId"`
	ChallengeNonce    string `json:"challengeNonce"`
	Side              string `json:"side"`
	Kind              string `json:"kind"`
	Payload           string `json:"payload"`
}

func (r PairingRelay) SigningBytes() ([]byte, error) {
	for _, id := range []string{r.AccountID, r.SessionID} {
		if validID(id) != nil {
			return nil, ErrInvalidWire
		}
	}
	if validDecimal(r.AccountGeneration, true) != nil || (r.Side != "initiator" && r.Side != "approver") || (r.Kind != "message" && r.Kind != "confirmation") {
		return nil, ErrInvalidWire
	}
	for _, value := range []string{r.ChallengeNonce, r.Payload} {
		if _, err := DecodeBase64(value, 32, 32); err != nil {
			return nil, err
		}
	}
	return canonical("harmonia/pairing-relay/v1", r.AccountID, r.AccountGeneration, r.SessionID, r.ChallengeNonce, r.Side, r.Kind, r.Payload), nil
}
func SignPairingRelay(r PairingRelay, key ed25519.PrivateKey) (string, error) {
	b, err := r.SigningBytes()
	if err != nil {
		return "", err
	}
	return sign(key, b)
}
func VerifyPairingRelay(r PairingRelay, signature string, trustedSideKey ed25519.PublicKey) error {
	b, err := r.SigningBytes()
	if err != nil {
		return err
	}
	return verify(trustedSideKey, b, signature)
}
