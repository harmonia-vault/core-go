package cryptox

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
)

// PasswordCredential 严格为密码 UTF-8 字节的 SHA256。
// 该值是可重放的密码等价凭据，不能作为 vault 钥匙或写日志。
func PasswordCredential(password string) [32]byte { return sha256.Sum256([]byte(password)) }

func GenerateEnvironmentKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

// ValueContext 作为数据 AEAD 附加数据受到认证。
type ValueContext struct {
	AccountID         string
	AccountGeneration string
	EnvironmentID     string
	KeyVersion        string
	Name              string
}

func (c ValueContext) AssociatedData() ([]byte, error) {
	if validID(c.AccountID) != nil || validID(c.EnvironmentID) != nil || validDecimal(c.AccountGeneration, true) != nil || validDecimal(c.KeyVersion, true) != nil || !validName(c.Name) {
		return nil, ErrInvalidWire
	}
	return canonical("harmonia/value/v1", c.AccountID, c.AccountGeneration, c.EnvironmentID, c.KeyVersion, c.Name), nil
}

// EncryptValue 生成随机 192 位 nonce，使用独立环境钥。
// 数据包为 nonce||密文||16 字节 Poly1305 标签。
func EncryptValue(key []byte, c ValueContext, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return encryptValueWithNonce(key, c, plaintext, nonce)
}

func encryptValueWithNonce(key []byte, c ValueContext, plaintext, nonce []byte) ([]byte, error) {
	if len(plaintext) > MaxValueBytes || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrInvalidWire
	}
	ad, err := c.AssociatedData()
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	packet := append([]byte(nil), nonce...)
	return aead.Seal(packet, nonce, plaintext, ad), nil
}

func DecryptValue(key []byte, c ValueContext, packet []byte) ([]byte, error) {
	if len(packet) < 40 || len(packet) > MaxValueBytes+40 {
		return nil, ErrInvalidWire
	}
	ad, err := c.AssociatedData()
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, packet[:24], packet[24:], ad)
}

// EnvelopeContext 将接收钥绑定到账号、环境及代际。
// RecipientGeneration 对设备为授权代际，对恢复为恢复代际。
// 接收公钥只有经过独立可信审批流程才能成为可信钥。
type EnvelopeContext struct {
	AccountID           string
	AccountGeneration   string
	EnvironmentID       string
	KeyVersion          string
	RecipientType       string
	RecipientID         string
	RecipientGeneration string
	RecipientPublicKey  string
}

func (c EnvelopeContext) Info() ([]byte, error) {
	if validID(c.AccountID) != nil || validID(c.EnvironmentID) != nil || validID(c.RecipientID) != nil || validDecimal(c.AccountGeneration, true) != nil || validDecimal(c.KeyVersion, true) != nil || validDecimal(c.RecipientGeneration, true) != nil {
		return nil, ErrInvalidWire
	}
	if c.RecipientType != "device" && c.RecipientType != "recovery" {
		return nil, ErrInvalidWire
	}
	if _, err := DecodeBase64(c.RecipientPublicKey, 32, 32); err != nil {
		return nil, err
	}
	return canonical("harmonia/envelope/v1", "32", "1", "3", c.AccountID, c.AccountGeneration, c.EnvironmentID, c.KeyVersion, c.RecipientType, c.RecipientID, c.RecipientGeneration, c.RecipientPublicKey), nil
}

// GenerateReceivingKey 返回独立 X25519 公钥和私钥字节。
func GenerateReceivingKey() (public, private []byte, err error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return sk.PublicKey().Bytes(), sk.Bytes(), nil
}

// WrapEnvironmentKey 使用 RFC9180 基础模式 DHKEM(X25519,HKDF-SHA256)、
// HKDF-SHA256 和 ChaCha20Poly1305，数据包为 enc32||ciphertext48。
// 管理设备对完整封套的签名提供发送者身份认证。
func WrapEnvironmentKey(environmentKey []byte, c EnvelopeContext) ([]byte, error) {
	if len(environmentKey) != 32 {
		return nil, ErrInvalidWire
	}
	info, err := c.Info()
	if err != nil {
		return nil, err
	}
	pkBytes, err := DecodeBase64(c.RecipientPublicKey, 32, 32)
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPublicKey(pkBytes)
	if err != nil {
		return nil, err
	}
	hpkePK, err := hpke.NewDHKEMPublicKey(pk)
	if err != nil {
		return nil, err
	}
	enc, sender, err := hpke.NewSender(hpkePK, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return nil, err
	}
	ciphertext, err := sender.Seal(nil, environmentKey)
	if err != nil {
		return nil, err
	}
	return append(enc, ciphertext...), nil
}

func UnwrapEnvironmentKey(private []byte, c EnvelopeContext, packet []byte) ([]byte, error) {
	if len(packet) != 80 || len(private) != 32 {
		return nil, ErrInvalidWire
	}
	info, err := c.Info()
	if err != nil {
		return nil, err
	}
	sk, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	if EncodeBase64(sk.PublicKey().Bytes()) != c.RecipientPublicKey {
		return nil, errors.New("recipient public key mismatch")
	}
	hpkeSK, err := hpke.NewDHKEMPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	receiver, err := hpke.NewRecipient(packet[:32], hpkeSK, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return nil, err
	}
	key, err := receiver.Open(nil, packet[32:])
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, ErrInvalidWire
	}
	return key, nil
}
