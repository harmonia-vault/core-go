package syncclient

import (
	"context"
	"crypto/ed25519"

	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
)

type DeviceChallenge struct {
	ChallengeID    string   `json:"challengeId"`
	Nonce          string   `json:"nonce"`
	ExpiresAt      int64    `json:"expiresAt"`
	SigningPayload []string `json:"signingPayload"`
}
type DeviceSession struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

// BindDevice 以登录会话申请一次性短时挑战，证明当前设备确实持有独立
// Ed25519 私钥后取得绑定会话。登录成功本身不构成设备可信。
// 挑战字节必须与本地账号、代际、设备、登录token哈希逐项匹配。
func (c *Client) BindDevice(ctx context.Context, signingKey ed25519.PrivateKey) (*Client, error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid local device signing key")
	}
	var challenge DeviceChallenge
	if err := c.request(ctx, "POST", c.endpointFor("/device-challenges"), struct{}{}, &challenge); err != nil {
		return nil, err
	}
	now := c.config.Now()
	if challenge.ExpiresAt <= now.Unix() || challenge.ExpiresAt > now.Add(5*time.Minute).Unix() {
		return nil, errors.New("device challenge is expired or excessively long-lived")
	}
	if _, err := cryptox.DecodeBase64(challenge.Nonce, 32, 32); err != nil {
		return nil, errors.New("invalid device challenge nonce")
	}
	if challenge.ChallengeID == "" {
		return nil, errors.New("missing device challenge identity")
	}
	proofContext, err := cryptox.NewDeviceSessionProof(c.config.AccountID, strconv.FormatUint(c.config.AccountGeneration, 10), c.config.DeviceID, c.config.Token, challenge.ChallengeID, challenge.Nonce, strconv.FormatInt(challenge.ExpiresAt, 10))
	if err != nil {
		return nil, errors.New("invalid locally-bound device challenge")
	}
	payload, err := proofContext.SigningBytes()
	if err != nil {
		return nil, err
	}
	var expected []string
	_ = json.Unmarshal(payload, &expected)
	if len(expected) != len(challenge.SigningPayload) {
		return nil, errors.New("unbound device signing challenge")
	}
	for i, value := range expected {
		if challenge.SigningPayload[i] != value {
			return nil, errors.New("device signing challenge does not match local identity/session")
		}
	}
	// 所有挑战字段来自受约束ASCII协议，JSON编码与server确定性array一致。
	signature, err := cryptox.SignDeviceSessionProof(proofContext, signingKey)
	if err != nil {
		return nil, err
	}
	proof := struct {
		ChallengeID string `json:"challengeId"`
		Signature   string `json:"signature"`
	}{challenge.ChallengeID, signature}
	var session DeviceSession
	if err := c.request(ctx, "POST", c.endpointFor("/device-sessions"), proof, &session); err != nil {
		return nil, err
	}
	if _, err := cryptox.DecodeBase64(session.Token, 32, 32); err != nil || session.ExpiresAt <= now.Unix() {
		return nil, errors.New("invalid device-bound session")
	}
	bound := *c
	bound.config = c.config
	bound.config.Token = session.Token
	return &bound, nil
}
