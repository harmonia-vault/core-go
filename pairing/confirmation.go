package pairing

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"

	"github.com/harmonia-vault/core-go/cryptox"
)

// confirmationMaterial 只处理原生 SPAKE2 输出，不导出未验证通道钥的替代入口。
// 该层使用标准 HKDF-SHA256/HMAC-SHA256，不实现任何群运算或 PAKE 原语。
func confirmationMaterial(c Context, raw, initiator, approver []byte) (a, b, channel []byte, err error) {
	if len(raw) != 64 || len(initiator) != 32 || len(approver) != 32 {
		return nil, nil, nil, ErrContext
	}
	hash, err := transcriptDigest(c, initiator, approver)
	if err != nil {
		return nil, nil, nil, err
	}
	derive := func(purpose string) ([]byte, error) { return hkdf.Key(sha256.New, raw, hash[:], purpose, 32) }
	keyA, err := derive("harmonia/pairing-confirm/initiator/v1")
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(keyA)
	keyB, err := derive("harmonia/pairing-confirm/approver/v1")
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(keyB)
	channel, err = derive("harmonia/pairing-channel/v1")
	if err != nil {
		return nil, nil, nil, err
	}
	mac := func(key []byte, role string) []byte {
		input, _ := json.Marshal([]string{"harmonia/pairing-confirmation/v1", role, cryptox.EncodeBase64(hash[:])})
		m := hmac.New(sha256.New, key)
		_, _ = m.Write(input)
		return m.Sum(nil)
	}
	return mac(keyA, "initiator"), mac(keyB, "approver"), channel, nil
}

func transcriptDigest(c Context, initiator, approver []byte) ([32]byte, error) {
	if len(initiator) != 32 || len(approver) != 32 {
		return [32]byte{}, ErrContext
	}
	contextBytes, err := c.CanonicalBytes()
	if err != nil {
		return [32]byte{}, err
	}
	transcript, err := json.Marshal([]string{"harmonia/pairing-transcript/v1", cryptox.EncodeBase64(contextBytes), cryptox.EncodeBase64(initiator), cryptox.EncodeBase64(approver)})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(transcript), nil
}
