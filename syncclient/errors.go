package syncclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ErrTrustInvalidated 表示当前账号/设备来源已经停止；后台控制器随后清除
// device/session/trust slots 并恢复 provider。普通 token 到期不触发这种清理。
var ErrTrustInvalidated = errors.New("current account/device authorization invalidated")

// 只保留可供界面分类的失败类型，不携带 URL、请求内容或底层错误文本。
var ErrRequestFailed = errors.New("HTTPS request failed")
var ErrResponseInvalid = errors.New("HTTPS response invalid")

type RequestError struct {
	Status            int
	Code              string
	RetryAfterSeconds int
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("server rejected request (HTTP %d, %s)", e.Status, e.Code)
}

// NewRequestError 将不可信服务端代码限制为已审查的固定协议枚举。
// 任意文本、hex、密码等价凭据或内部信息均归一为 request_rejected。
func NewRequestError(status int, code string) *RequestError {
	fault := &RequestError{Status: status, Code: "request_rejected"}
	if knownFaultCodes[code] {
		fault.Code = code
	}
	return fault
}

// 邮件限流必须带有界等待秒数；其他错误不允许携带该字段。
func NewRequestErrorWithRetry(status int, code string, retryAfterSeconds *int) *RequestError {
	fault := NewRequestError(status, code)
	limited := fault.Code == "email_request_limited" || fault.Code == "email_ip_blocked"
	if !limited {
		if retryAfterSeconds != nil {
			return NewRequestError(status, "request_rejected")
		}
		return fault
	}
	if status != http.StatusTooManyRequests || retryAfterSeconds == nil || *retryAfterSeconds < 1 || *retryAfterSeconds > 86400 {
		return NewRequestError(status, "request_rejected")
	}
	fault.RetryAfterSeconds = *retryAfterSeconds
	return fault
}

func parseRequestError(response *http.Response) *RequestError {
	fault := NewRequestError(response.StatusCode, "")
	// 错误体只读取固定小上限；未知字段、额外 JSON、任意文本不进入日志/错误。
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err == nil && len(data) <= 4096 {
		var wire struct {
			Error             string `json:"error"`
			RetryAfterSeconds *int   `json:"retryAfterSeconds,omitempty"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&wire) == nil {
			var extra any
			if decoder.Decode(&extra) == io.EOF && knownFaultCodes[wire.Error] {
				fault = NewRequestErrorWithRetry(response.StatusCode, wire.Error, wire.RetryAfterSeconds)
			}
		}
	}
	return fault
}
func (c *Client) rejection(response *http.Response, bootRoute bool) error {
	fault := parseRequestError(response)
	invalid := fault.Status == 401 && fault.Code == "generation_stale" ||
		fault.Status == 403 && (fault.Code == "device_untrusted" || bootRoute && fault.Code == "no_current_grant")
	if !invalid {
		return fault
	}
	// 身份始终取本地绑定上下文，不信错误体回显 account/device。
	var invalidateErr error
	if fault.Code == "no_current_grant" {
		invalidateErr = c.config.Engine.InvalidateAuthorizationsAtEpoch(c.epoch)
	} else {
		invalidateErr = c.config.Engine.LogoutAtEpoch(c.epoch)
	}
	if invalidateErr != nil {
		return invalidateErr
	}
	return errors.Join(ErrTrustInvalidated, fault)
}
