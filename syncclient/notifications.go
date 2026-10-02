package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

var (
	ErrNotificationUnavailable   = errors.New("notification connection unavailable")
	ErrNotificationProtocol      = errors.New("notification metadata rejected")
	ErrNotificationAuthorization = errors.New("notification authorization refresh required")
)

// NotificationHint 仅用于提示拉取；它不是已验证事件，也不能推进任何本地检查点。
type NotificationHint struct {
	AccountID         string `json:"accountId"`
	AccountGeneration string `json:"accountGeneration"`
	Sequence          uint64 `json:"sequence"`
}

// NotificationSubscription 只允许一个读取者；Close 可与读取或心跳并行。
// 账号、代际和本地 session epoch 取建立连接时的受信上下文。
type NotificationSubscription struct {
	client     *Client
	connection *websocket.Conn
	minimum    uint64
	last       uint64
	seen       bool
	close      sync.Once
}

// OpenNotifications 每次连接都申请新的单次短票据。失败不重用旧票据，不经 URL
// 传递 token，不允许重定向，不关闭 TLS 证书或主机名验证。
func (c *Client) OpenNotifications(ctx context.Context) (*NotificationSubscription, error) {
	var ticket struct {
		Ticket    string `json:"ticket"`
		ExpiresAt int64  `json:"expiresAt"`
		Sequence  uint64 `json:"sequence"`
	}
	if err := c.request(ctx, http.MethodPost, c.endpointFor("/notification-tickets"), struct{}{}, &ticket); err != nil {
		return nil, err
	}
	now := c.config.Now().Unix()
	if _, err := cryptox.DecodeBase64(ticket.Ticket, 32, 32); err != nil || ticket.ExpiresAt <= now || ticket.ExpiresAt > now+31 || ticket.Sequence > 9007199254740991 || ticket.Sequence < c.config.Engine.State().Cloud.Sequence {
		return nil, ErrNotificationProtocol
	}
	u := c.endpointFor("/notifications")
	u.Scheme = "wss"
	if u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		return nil, ErrNotificationProtocol
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+ticket.Ticket)
	header.Set("X-Harmonia-Device-Id", c.config.DeviceID)
	header.Set("X-Harmonia-Account-Generation", strconv.FormatUint(c.config.AccountGeneration, 10))
	header.Set("Cache-Control", "no-store")
	connection, response, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPClient: c.http, HTTPHeader: header, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		// 库错误可能包含服务器关闭原因、握手头或响应正文；只返回固定错误码。
		if response != nil && response.StatusCode != http.StatusSwitchingProtocols && response.Body != nil {
			return nil, c.rejection(response, false)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrNotificationUnavailable
	}
	connection.SetReadLimit(1024)
	if c.config.Engine.State().SessionEpoch != c.epoch {
		_ = connection.CloseNow()
		return nil, localstate.ErrLocalSession
	}
	return &NotificationSubscription{client: c, connection: connection, minimum: ticket.Sequence}, nil
}

func (s *NotificationSubscription) Close() {
	if s != nil {
		s.close.Do(func() { _ = s.connection.CloseNow() })
	}
}

// Read 严格接收固定的三个元数据字段。重复提示可交由调用方合并；倒退序号、
// 跨账号/代际、额外字段、重复 JSON 字段和二进制数据均终止本连接。
func (s *NotificationSubscription) Read(ctx context.Context) (NotificationHint, error) {
	if s.client.config.Engine.State().SessionEpoch != s.client.epoch {
		s.Close()
		return NotificationHint{}, localstate.ErrLocalSession
	}
	kind, data, err := s.connection.Read(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return NotificationHint{}, ctx.Err()
		}
		if websocket.CloseStatus(err) == websocket.StatusCode(4003) {
			return NotificationHint{}, ErrNotificationAuthorization
		}
		return NotificationHint{}, ErrNotificationUnavailable
	}
	hint, err := decodeNotification(data)
	if kind != websocket.MessageText || err != nil || hint.AccountID != s.client.config.AccountID || hint.AccountGeneration != strconv.FormatUint(s.client.config.AccountGeneration, 10) || hint.Sequence < s.minimum || s.seen && hint.Sequence < s.last {
		s.Close()
		return NotificationHint{}, ErrNotificationProtocol
	}
	if s.client.config.Engine.State().SessionEpoch != s.client.epoch {
		s.Close()
		return NotificationHint{}, localstate.ErrLocalSession
	}
	s.last, s.seen = hint.Sequence, true
	return hint, nil
}

// Watch 持续读取并使用库的 Ping/Pong 检查断链。callback 必须快速返回；守护进程
// 仅在其中写入一个合并唤醒信号，实际网络和验签仍由唯一 owner 串行执行。
func (s *NotificationSubscription) Watch(ctx context.Context, callback func(NotificationHint)) error {
	if callback == nil {
		s.Close()
		return ErrNotificationProtocol
	}
	watchCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(watchCtx, 10*time.Second)
				err := s.connection.Ping(pingCtx)
				pingCancel()
				if err != nil {
					s.Close()
					return
				}
			}
		}
	}()
	defer func() { cancel(); s.Close(); <-done }()
	var last uint64
	seen := false
	for {
		hint, err := s.Read(watchCtx)
		if err != nil {
			return err
		}
		if !seen || last != hint.Sequence {
			callback(hint)
			last, seen = hint.Sequence, true
		}
	}
}

func decodeNotification(data []byte) (NotificationHint, error) {
	var hint NotificationHint
	if len(data) > 1024 {
		return hint, ErrNotificationProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return hint, ErrNotificationProtocol
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err = decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return hint, ErrNotificationProtocol
		}
		seen[name] = true
		switch name {
		case "accountId":
			err = decoder.Decode(&hint.AccountID)
		case "accountGeneration":
			err = decoder.Decode(&hint.AccountGeneration)
		case "sequence":
			var value json.Token
			value, err = decoder.Token()
			number, ok := value.(json.Number)
			if err != nil || !ok {
				return hint, ErrNotificationProtocol
			}
			hint.Sequence, err = strconv.ParseUint(number.String(), 10, 64)
			if err != nil || strconv.FormatUint(hint.Sequence, 10) != number.String() {
				return hint, ErrNotificationProtocol
			}
		default:
			return hint, ErrNotificationProtocol
		}
		if err != nil {
			return hint, ErrNotificationProtocol
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || len(seen) != 3 || hint.Sequence > 9007199254740991 {
		return hint, ErrNotificationProtocol
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return hint, ErrNotificationProtocol
	}
	return hint, nil
}
