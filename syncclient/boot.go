package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// BootDevice 只用于已经被管理手机批准的设备；从受保护本地签名钥重新取
// 设备绑定会话，不需要登录 password-equivalent，也不自动建立设备信任。
func (c *Client) BootDevice(ctx context.Context, signingKey ed25519.PrivateKey) (*Client, error) {
	if c.config.Token != "" {
		return nil, errors.New("boot proof must not carry a login credential")
	}
	verifier, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || len(signingKey) != ed25519.PrivateKeySize || verifier.trust.AccountID != c.config.AccountID || verifier.trust.AccountGeneration != c.config.AccountGeneration || verifier.trust.DeviceID != c.config.DeviceID || !bytes.Equal(signingKey.Public().(ed25519.PublicKey), verifier.trust.DeviceSigningPublicKey) {
		return nil, errors.New("boot requires exact locally pinned device trust")
	}
	request := struct {
		DeviceID          string `json:"deviceId"`
		AccountGeneration string `json:"accountGeneration"`
	}{c.config.DeviceID, strconv.FormatUint(c.config.AccountGeneration, 10)}
	var challenge DeviceChallenge
	if err := c.request(ctx, "POST", c.endpointFor("/boot-challenges"), request, &challenge); err != nil {
		return nil, err
	}
	now := c.config.Now()
	if challenge.ExpiresAt <= now.Unix() || challenge.ExpiresAt > now.Add(5*time.Minute).Unix() {
		return nil, errors.New("boot challenge is expired or excessively long-lived")
	}
	receivingPublic, err := cryptox.DecodeBase64(verifier.receivingPublicKey, 32, 32)
	if err != nil {
		return nil, err
	}
	proof, err := cryptox.NewDeviceBootProof(c.config.AccountID, request.AccountGeneration, c.config.DeviceID, verifier.trust.DeviceSigningPublicKey, receivingPublic, challenge.ChallengeID, challenge.Nonce, strconv.FormatInt(challenge.ExpiresAt, 10))
	if err != nil {
		return nil, errors.New("invalid locally-bound boot challenge")
	}
	wire, err := proof.SigningBytes()
	if err != nil {
		return nil, err
	}
	var expected []string
	_ = json.Unmarshal(wire, &expected)
	if len(challenge.SigningPayload) != len(expected) {
		return nil, errors.New("unbound boot signing challenge")
	}
	for i, value := range expected {
		if challenge.SigningPayload[i] != value {
			return nil, errors.New("boot challenge does not match exact account/device/public keys")
		}
	}
	signature, err := cryptox.SignDeviceBootProof(proof, signingKey)
	if err != nil {
		return nil, err
	}
	finish := struct {
		DeviceID          string `json:"deviceId"`
		AccountGeneration string `json:"accountGeneration"`
		ChallengeID       string `json:"challengeId"`
		Signature         string `json:"signature"`
	}{request.DeviceID, request.AccountGeneration, challenge.ChallengeID, signature}
	var session DeviceSession
	if err = c.request(ctx, "POST", c.endpointFor("/boot-sessions"), finish, &session); err != nil {
		return nil, err
	}
	if _, err = cryptox.DecodeBase64(session.Token, 32, 32); err != nil || session.ExpiresAt <= c.config.Now().Unix() {
		return nil, errors.New("invalid boot device-bound session")
	}
	if c.config.Engine.State().SessionEpoch != c.epoch {
		return nil, localstate.ErrLocalSession
	}
	bound := *c
	bound.config = c.config
	bound.config.Token = session.Token
	return &bound, nil
}
