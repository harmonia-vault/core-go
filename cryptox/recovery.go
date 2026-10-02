package cryptox

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// RecoveryKeys 仅为密码学底座，完整恢复及恢复码轮换流程尚未完成。
// 恢复签名钥和恢复接收钥各自用于独立用途。
type RecoveryKeys struct {
	SigningPrivate   ed25519.PrivateKey
	SigningPublic    ed25519.PublicKey
	ReceivingPrivate []byte
	ReceivingPublic  []byte
}

func GenerateRecoverySeed() ([]byte, error) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	return seed, err
}

func DeriveRecoveryKeys(seed []byte, accountID, accountGeneration, recoveryGeneration string) (RecoveryKeys, error) {
	if len(seed) != 32 || validID(accountID) != nil || validDecimal(accountGeneration, true) != nil || validDecimal(recoveryGeneration, true) != nil {
		return RecoveryKeys{}, ErrInvalidWire
	}
	derive := func(purpose string) ([]byte, error) {
		info := canonical("harmonia/recovery-kdf/v1", purpose, accountID, accountGeneration, recoveryGeneration)
		return hkdf.Key(sha256.New, seed, nil, string(info), 32)
	}
	signingSeed, err := derive("ed25519-signing")
	if err != nil {
		return RecoveryKeys{}, err
	}
	receivingSeed, err := derive("x25519-receiving")
	if err != nil {
		return RecoveryKeys{}, err
	}
	sk := ed25519.NewKeyFromSeed(signingSeed)
	xsk, err := ecdh.X25519().NewPrivateKey(receivingSeed)
	if err != nil {
		return RecoveryKeys{}, err
	}
	return RecoveryKeys{sk, sk.Public().(ed25519.PublicKey), xsk.Bytes(), xsk.PublicKey().Bytes()}, nil
}

// 恢复码以规范无 padding base32 包含完整 256 位种子。
// 分组仅用于展示，恢复码不含用户身份或密码。
func EncodeRecoveryCode(seed []byte) (string, error) {
	if len(seed) != 32 {
		return "", ErrInvalidWire
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed), nil
}

func DecodeRecoveryCode(code string) ([]byte, error) {
	code = strings.ReplaceAll(code, "-", "")
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(code)
	if err != nil || len(seed) != 32 {
		return nil, ErrInvalidWire
	}
	canonicalCode, _ := EncodeRecoveryCode(seed)
	if canonicalCode != code {
		return nil, ErrInvalidWire
	}
	return seed, nil
}
