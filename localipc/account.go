package localipc

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

// AccountRequest 仅表示用户明确操作。凭据是 SHA256(password) 的32字节等价物，
// 只在经 OS 双向认证的本机帧中传递；不接收 Vault/信任/钥匙/用户路径。
type AccountRequest struct {
	Action             string `json:"action"`
	Endpoint           string `json:"endpoint,omitempty"`
	Email              string `json:"email,omitempty"`
	Credential         []byte `json:"credential,omitempty"`
	ApproverDeviceID   string `json:"approverDeviceId,omitempty"`
	CertificateVersion string `json:"certificateVersion,omitempty"`
	PairingID          string `json:"pairingId,omitempty"`
}

// AccountState 是受认证本机用户可见的进度，不返回会话 token、证书或钥匙。
// ShortCode 只在尚未完成 PAKE 的 pairing 阶段返回，不能作为云端登录凭据。
type AccountState struct {
	Phase     string `json:"phase"`
	PairingID string `json:"pairingId,omitempty"`
	ShortCode string `json:"shortCode,omitempty"`
	Accepted  bool   `json:"accepted"`
	Applied   bool   `json:"applied"`
}

// AccountHandler 的 owner 持有唯一 Store；启动的配对任务须独立于 CLI 连接。
// 取消/退出必须等待任务收尾。已有 sealed receipt/结果未知时只能查询原 ID。
type AccountHandler func(context.Context, AccountRequest) (AccountState, error)

var ErrAccountPending = errors.New("IPC account operation pending")
var ErrAccountClosed = errors.New("IPC account owner closed")

func validateAccountRequest(r AccountRequest) error {
	switch r.Action {
	case "login":
		u, err := url.Parse(r.Endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(r.Endpoint) > 2048 || strings.ContainsAny(r.Endpoint, "\x00\r\n") || !utf8.ValidString(r.Endpoint) {
			return ErrProtocol
		}
		if len(r.Email) == 0 || len(r.Email) > 320 || !utf8.ValidString(r.Email) || !strings.ContainsRune(r.Email, '@') || strings.ContainsAny(r.Email, "\x00\r\n") || len(r.Credential) != 32 || r.ApproverDeviceID != "" || r.CertificateVersion != "" || r.PairingID != "" {
			return ErrProtocol
		}
	case "pair":
		if r.Endpoint != "" || r.Email != "" || len(r.Credential) != 0 || !idPattern.MatchString(r.ApproverDeviceID) || r.PairingID != "" || (r.CertificateVersion != "2" && r.CertificateVersion != "3" && r.CertificateVersion != "4" && r.CertificateVersion != "5") {
			return ErrProtocol
		}
	case "pair-status", "pair-cancel":
		if r.Endpoint != "" || r.Email != "" || len(r.Credential) != 0 || r.ApproverDeviceID != "" || r.CertificateVersion != "" || !idPattern.MatchString(r.PairingID) {
			return ErrProtocol
		}
	default:
		return ErrProtocol
	}
	return nil
}
func validateAccountState(s AccountState) error {
	if s.Applied && !s.Accepted {
		return ErrProtocol
	}
	switch s.Phase {
	case "idle", "logged-in":
		if s.PairingID != "" || s.ShortCode != "" || s.Accepted || s.Applied {
			return ErrProtocol
		}
	case "pairing":
		if !idPattern.MatchString(s.PairingID) || len(s.ShortCode) != 8 || s.Accepted || s.Applied {
			return ErrProtocol
		}
		for _, c := range s.ShortCode {
			if c < '0' || c > '9' {
				return ErrProtocol
			}
		}
	case "pending", "failed", "cancelled":
		if !idPattern.MatchString(s.PairingID) || s.ShortCode != "" || s.Accepted || s.Applied {
			return ErrProtocol
		}
	case "accepted":
		if !idPattern.MatchString(s.PairingID) || s.ShortCode != "" || !s.Accepted {
			return ErrProtocol
		}
	default:
		return ErrProtocol
	}
	return nil
}
func (s *Server) dispatchAccount(ctx context.Context, r Request) Response {
	response := Response{Version: Version}
	if s.config.Account == nil {
		response.Code = "account_unavailable"
		return response
	}
	state, err := s.config.Account(ctx, *r.Account)
	if err != nil {
		switch {
		case errors.Is(err, ErrAccountPending):
			response.Code = "account_pending"
		case errors.Is(err, ErrAccountClosed):
			response.Code = "account_closed"
		case errors.Is(err, context.DeadlineExceeded):
			response.Code = "request_expired"
		case errors.Is(err, context.Canceled):
			response.Code = "request_canceled"
		default:
			response.Code = "account_failed"
		}
		return response
	}
	if validateAccountState(state) != nil {
		response.Code = "account_failed"
		return response
	}
	response.OK = true
	response.Account = &state
	return response
}
