package mobilebridge

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"github.com/harmonia-vault/core-go/syncclient"
)

// ExecuteAccount 仅接受无设备密钥的账号及验证邮件操作。CA 由原生提供；不接收
// 设备、密封状态或存储回调，不输出登录 token，也不能执行保险库操作。
func ExecuteAccount(raw string, additionalCA []byte) (string, error) {
	c, err := parseWorkflowCommand(raw)
	if err != nil {
		return "", err
	}
	switch c.operation {
	case "register", "verifyEmail", "requestVerificationEmail", "loginAccount":
	default:
		return "", errInput
	}
	client, err := workflowHTTPClient(additionalCA)
	if err != nil {
		return "", err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var data any
	switch c.operation {
	case "register":
		data, err = mobileworkflow.RegisterAccount(ctx, client, c.endpoint, c.fields["email"], c.fields["password"])
	case "requestVerificationEmail":
		err = mobileworkflow.RequestVerificationEmail(ctx, client, c.endpoint, c.fields["email"])
		data = map[string]bool{"accepted": err == nil}
	case "verifyEmail":
		err = mobileworkflow.VerifyAccountEmail(ctx, client, c.endpoint, mobileworkflow.EmailVerification{
			AccountID: c.fields["accountId"], AccountGeneration: c.fields["accountGeneration"],
			Code: c.fields["code"],
		})
	case "loginAccount":
		password := c.fields["password"]
		if len(password) == 0 || len(password) > 16384 {
			return "", errInput
		}
		hash := cryptox.PasswordCredential(password)
		defer clear(hash[:])
		_, err = syncclient.Login(ctx, syncclient.LoginConfig{
			Endpoint: c.endpoint, HTTPClient: client, Email: c.fields["email"],
			Credential: hex.EncodeToString(hash[:]),
		})
		data = accountLoginResult{Authenticated: err == nil, TrustedDevice: false}
	}
	out := map[string]any{"version": 1, "ok": err == nil, "experimental": true}
	if limited := emailLimitFailure(err); limited != nil {
		return encode(limited)
	}
	if err != nil {
		out["code"] = "REJECTED"
		if code := emailCodeFailure(err); code != "" {
			out["code"] = code
		}
	} else if data != nil {
		out["data"] = data
	}
	return encode(out)
}
