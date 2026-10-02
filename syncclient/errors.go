package syncclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
)

// ErrTrustInvalidated 表示当前账号/设备来源已经停止；后台控制器随后清除
// device/session/trust slots 并恢复 provider。普通 token 到期不触发这种清理。
var ErrTrustInvalidated = errors.New("current account/device authorization invalidated")

type RequestError struct {
	Status int
	Code   string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("server rejected request (HTTP %d, %s)", e.Status, e.Code)
}

var faultCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func parseRequestError(response *http.Response) *RequestError {
	fault := &RequestError{Status: response.StatusCode, Code: "request_rejected"}
	// 错误体只读取固定小上限；未知字段、额外 JSON、任意文本不进入日志/错误。
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err == nil && len(data) <= 4096 {
		var wire struct {
			Error string `json:"error"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&wire) == nil {
			var extra any
			if decoder.Decode(&extra) == io.EOF && faultCode.MatchString(wire.Error) {
				fault.Code = wire.Error
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
