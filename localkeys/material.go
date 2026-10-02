package localkeys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

// DeviceKeys 只保存钥匙材料，不把登录或本地存储当作可信设备授权。
type DeviceKeys struct {
	DeviceID         string `json:"deviceId"`
	SigningSeed      []byte `json:"signingSeed"`
	SigningPublic    []byte `json:"signingPublic"`
	ReceivingPrivate []byte `json:"receivingPrivate"`
	ReceivingPublic  []byte `json:"receivingPublic"`
}

func GenerateDeviceKeys(deviceID string) (DeviceKeys, error) {
	if !identityPattern.MatchString(deviceID) {
		return DeviceKeys{}, ErrCorrupt
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return DeviceKeys{}, err
	}
	defer clear(private)
	receive, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return DeviceKeys{}, err
	}
	return DeviceKeys{DeviceID: deviceID, SigningSeed: private.Seed(), SigningPublic: pub, ReceivingPrivate: receive.Bytes(), ReceivingPublic: receive.PublicKey().Bytes()}, nil
}
func (k DeviceKeys) validate() error {
	if !identityPattern.MatchString(k.DeviceID) || len(k.SigningSeed) != ed25519.SeedSize || len(k.SigningPublic) != ed25519.PublicKeySize || len(k.ReceivingPrivate) != 32 || len(k.ReceivingPublic) != 32 {
		return ErrCorrupt
	}
	sign := ed25519.NewKeyFromSeed(k.SigningSeed)
	if !bytes.Equal(sign.Public().(ed25519.PublicKey), k.SigningPublic) {
		clear(sign)
		return ErrCorrupt
	}
	clear(sign)
	receive, err := ecdh.X25519().NewPrivateKey(k.ReceivingPrivate)
	if err != nil || !bytes.Equal(receive.PublicKey().Bytes(), k.ReceivingPublic) {
		return ErrCorrupt
	}
	return nil
}
func (v *Vault) SaveDeviceKeys(keys DeviceKeys) error {
	if err := keys.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	defer clear(data)
	v.mu.Lock()
	defer v.mu.Unlock()
	trust, err := v.loadTrustRecordLocked()
	if err == nil && !sameDeviceIdentity(keys, trust) {
		return ErrIdentity
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return v.saveLocked("device-v1", data)
}
func (v *Vault) LoadDeviceKeys() (DeviceKeys, error) {
	data, err := v.Load("device-v1")
	if err != nil {
		return DeviceKeys{}, err
	}
	defer clear(data)
	var keys DeviceKeys
	if err := strictJSON(data, &keys); err != nil {
		return DeviceKeys{}, err
	}
	if err := keys.validate(); err != nil {
		return DeviceKeys{}, err
	}
	return keys, nil
}

// LoginSession 不包含密码派生凭据；登录成功不授予设备环境权限。
type LoginSession struct {
	Endpoint          string `json:"endpoint"`
	AccountID         string `json:"accountId"`
	AccountGeneration uint64 `json:"accountGeneration"`
	Token             string `json:"token"`
	ExpiresAt         string `json:"expiresAt"`
}

func (s LoginSession) validate() error {
	if !validEndpoint(s.Endpoint) || !identityPattern.MatchString(s.AccountID) || s.AccountGeneration == 0 || len(s.Token) < 16 || len(s.Token) > 4096 || strings.ContainsAny(s.Token, "\x00\r\n") {
		return ErrCorrupt
	}
	if _, err := time.Parse(time.RFC3339Nano, s.ExpiresAt); err != nil {
		return ErrCorrupt
	}
	return nil
}
func (v *Vault) SaveSession(session LoginSession) error {
	if err := session.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	defer clear(data)
	v.mu.Lock()
	defer v.mu.Unlock()
	trust, err := v.loadTrustRecordLocked()
	if err == nil && !sameSessionIdentity(session, trust) {
		return ErrIdentity
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return v.saveLocked("session-v1", data)
}
func (v *Vault) LoadSession() (LoginSession, error) {
	data, err := v.Load("session-v1")
	if err != nil {
		return LoginSession{}, err
	}
	defer clear(data)
	var session LoginSession
	if err := strictJSON(data, &session); err != nil {
		return LoginSession{}, err
	}
	if err := session.validate(); err != nil {
		return LoginSession{}, err
	}
	return session, nil
}
