package mobilebridge

import (
	"errors"

	"github.com/harmonia-vault/core-go/syncclient"
)

// 只把已审查的邮件限流枚举和有界秒数交给 UI，不透传服务端文本。
func emailLimitFailure(err error) map[string]any {
	var fault *syncclient.RequestError
	if !errors.As(err, &fault) || fault.RetryAfterSeconds <= 0 {
		return nil
	}
	return map[string]any{"version": 1, "ok": false, "experimental": true,
		"code": "EMAIL_RATE_LIMITED", "retryAfterSeconds": fault.RetryAfterSeconds}
}
