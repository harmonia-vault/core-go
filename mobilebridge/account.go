package mobilebridge

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
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
		out["code"] = accountFailure(c.operation, err)
	} else if data != nil {
		out["data"] = data
	}
	return encode(out)
}

// 账号入口只公开固定类别；登录的 unauthorized 不区分账号不存在、密码错误或未验证。
func accountFailure(operation string, err error) string {
	if code := emailCodeFailure(err); code != "" {
		return code
	}
	if errors.Is(err, syncclient.ErrRequestFailed) {
		return "NETWORK_ERROR"
	}
	if errors.Is(err, syncclient.ErrResponseInvalid) {
		return "SERVER_RESPONSE_INVALID"
	}
	var fault *syncclient.RequestError
	if !errors.As(err, &fault) {
		return "ACCOUNT_REQUEST_FAILED"
	}
	switch fault.Code {
	case "account_exists":
		return "ACCOUNT_EXISTS"
	case "account_format_unsupported":
		return "ACCOUNT_FORMAT_UNSUPPORTED"
	case "registration_disabled":
		return "REGISTRATION_DISABLED"
	case "email_invalid":
		return "EMAIL_INVALID"
	case "email_delivery_failed":
		return "EMAIL_DELIVERY_FAILED"
	case "email_verification_unavailable":
		return "EMAIL_UNAVAILABLE"
	case "email_verification_required":
		return "EMAIL_VERIFICATION_REQUIRED"
	case "account_changed", "generation_stale":
		return "ACCOUNT_CHANGED"
	case "unauthorized":
		if operation == "loginAccount" {
			return "LOGIN_FAILED"
		}
	}
	switch {
	case fault.Status == http.StatusUpgradeRequired:
		return "SERVER_RESPONSE_INVALID"
	case fault.Status == http.StatusTooManyRequests:
		return "REQUEST_RATE_LIMITED"
	case fault.Status >= 500:
		return "SERVER_UNAVAILABLE"
	default:
		return "ACCOUNT_REQUEST_FAILED"
	}
}
