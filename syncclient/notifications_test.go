package syncclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

type notificationFixture struct {
	mu              sync.Mutex
	crypto          *cryptoFixture
	engine          *localstate.Engine
	client          *Client
	server          *httptest.Server
	sequence        uint64
	tickets         int
	ticket          string
	connections     []*websocket.Conn
	ready           chan *websocket.Conn
	events          []Event
	rejectHandshake bool
}

func newNotificationFixture(t *testing.T) *notificationFixture {
	t.Helper()
	f := &notificationFixture{crypto: newCryptoFixture(t), engine: testEngine(t), sequence: 1, ready: make(chan *websocket.Conn, 8)}
	f.events = []Event{f.crypto.event(t, 1, "initial-synthetic")}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.URL.RawQuery != "" && !strings.HasSuffix(r.URL.Path, "/pull") || r.Header.Get("X-Harmonia-Device-Id") != "dev" || r.Header.Get("X-Harmonia-Account-Generation") != "1" {
			t.Error("通知连接身份或HTTPS边界错误")
		}
		f.mu.Lock()
		if strings.HasSuffix(r.URL.Path, "/notification-tickets") {
			defer f.mu.Unlock()
			body, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || string(body) != "{}" || r.Header.Get("Authorization") != "Bearer "+cryptox.EncodeBase64(make([]byte, 32)) {
				t.Error("票据请求错误")
			}
			f.tickets++
			f.ticket = cryptox.EncodeBase64(append([]byte{byte(f.tickets)}, make([]byte, 31)...))
			_ = json.NewEncoder(w).Encode(map[string]any{"ticket": f.ticket, "expiresAt": fixedNow.Add(30 * time.Second).Unix(), "sequence": f.sequence})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/notifications") {
			if r.Header.Get("Authorization") != "Bearer "+f.ticket {
				t.Error("WSS没有使用新单次票据")
			}
			if f.rejectHandshake {
				f.mu.Unlock()
				w.WriteHeader(400)
				_, _ = io.WriteString(w, `{"error":"synthetic_secret_lowercase"}`)
				return
			}
			sequence := f.sequence
			f.mu.Unlock()
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			f.mu.Lock()
			f.connections = append(f.connections, conn)
			f.mu.Unlock()
			hint, _ := json.Marshal(NotificationHint{AccountID: "acct", AccountGeneration: "1", Sequence: sequence})
			_ = conn.Write(context.Background(), websocket.MessageText, hint)
			f.ready <- conn
			<-conn.CloseRead(context.Background()).Done()
			_ = conn.CloseNow()
			return
		}
		defer f.mu.Unlock()
		pull := f.crypto.pull(f.sequence)
		if r.URL.Query().Get("scope") == "authorizations" {
			pull.Scope = "authorizations"
		} else {
			after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
			for _, event := range f.events {
				if event.Sequence > after {
					pull.Events = append(pull.Events, event)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(pull)
	}))
	t.Cleanup(func() {
		f.mu.Lock()
		connections := append([]*websocket.Conn(nil), f.connections...)
		f.mu.Unlock()
		for _, c := range connections {
			_ = c.CloseNow()
		}
		f.server.Close()
	})
	f.client = testClient(t, f.server, f.engine, f.crypto.verifier)
	return f
}
func (f *notificationFixture) next(t *testing.T) *websocket.Conn {
	t.Helper()
	select {
	case c := <-f.ready:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("WSS未就绪")
		return nil
	}
}
func (f *notificationFixture) hint(t *testing.T, conn *websocket.Conn, seq uint64) {
	t.Helper()
	data, _ := json.Marshal(NotificationHint{AccountID: "acct", AccountGeneration: "1", Sequence: seq})
	check(t, conn.Write(context.Background(), websocket.MessageText, data))
}
func TestNotificationsAreHintsAndReconnectUsesDurablePull(t *testing.T) {
	f := newNotificationFixture(t)
	ctx := context.Background()
	sub, err := f.client.OpenNotifications(ctx)
	check(t, err)
	conn := f.next(t)
	hint, err := sub.Read(ctx)
	check(t, err)
	if hint.Sequence != 1 || f.engine.State().Cloud.Sequence != 0 {
		t.Fatal("连接提示推进了检查点")
	}
	_, err = f.client.Pull(ctx)
	check(t, err)
	f.hint(t, conn, 9007199254740991)
	_, err = sub.Read(ctx)
	check(t, err)
	if f.engine.State().Cloud.Sequence != 1 {
		t.Fatal("未验证提示推进了检查点")
	}
	sub.Close()
	f.mu.Lock()
	f.sequence = 2
	f.events = append(f.events, f.crypto.event(t, 2, "missed-while-offline"))
	f.mu.Unlock()
	sub, err = f.client.OpenNotifications(ctx)
	check(t, err)
	defer sub.Close()
	f.next(t)
	hint, err = sub.Read(ctx)
	check(t, err)
	if hint.Sequence != 2 || f.engine.State().Cloud.Sequence != 1 {
		t.Fatal("重连提示直接应用")
	}
	_, err = f.client.Pull(ctx)
	check(t, err)
	if f.engine.State().Cloud.Environments["env"].Values["TOKEN"] != "missed-while-offline" || f.tickets != 2 {
		t.Fatal("重连没有持久补漏或重用了票据")
	}
}
func TestPausedNotificationOnlyAuthorizationRefreshAndSignedRevoke(t *testing.T) {
	f := newNotificationFixture(t)
	ctx := context.Background()
	_, err := f.client.Pull(ctx)
	check(t, err)
	check(t, f.engine.Activate("env", 1, fixedNow))
	check(t, f.engine.SetOverride("env", "TOKEN", "local-synthetic", fixedNow))
	check(t, f.engine.SetPaused(true))
	sub, err := f.client.OpenNotifications(ctx)
	check(t, err)
	defer sub.Close()
	conn := f.next(t)
	_, err = sub.Read(ctx)
	check(t, err)
	f.mu.Lock()
	f.sequence = 2
	f.events = append(f.events, f.crypto.event(t, 2, "pending-synthetic"))
	f.mu.Unlock()
	f.hint(t, conn, 2)
	_, err = sub.Read(ctx)
	check(t, err)
	_, err = f.client.RefreshAuthorizations(ctx)
	check(t, err)
	state := f.engine.State()
	if state.Cloud.Sequence != 1 || state.Cloud.AuthorizationSequence != 2 || state.Cloud.Environments["env"].Values["TOKEN"] != "initial-synthetic" {
		t.Fatal("暂停通知应用了普通数据")
	}
	revoked := f.crypto.grant.Grant
	revoked.Role = "none"
	revoked.Envelope = ""
	revoked.GrantGeneration = "2"
	revoked.IdempotencyKey = "revoke-2"
	signed := f.crypto.resignGrant(t, revoked)
	f.mu.Lock()
	f.crypto.grant = signed
	f.sequence = 3
	f.mu.Unlock()
	go func() { _ = conn.Close(websocket.StatusCode(4003), "synthetic_secret_close_reason") }()
	_, err = sub.Read(ctx)
	if !errors.Is(err, ErrNotificationAuthorization) || strings.Contains(err.Error(), "synthetic_secret") {
		t.Fatal("关闭原因泄露或未经重新验证执行撤销")
	}
	if len(f.engine.State().Cloud.Environments) != 1 {
		t.Fatal("4003直接视为撤销")
	}
	_, err = f.client.RefreshAuthorizations(ctx)
	check(t, err)
	if len(f.engine.State().Cloud.Environments) != 0 || len(f.engine.State().Overrides) != 0 {
		t.Fatal("签名撤销未清缓存/override")
	}
}
func TestNotificationRejectsMetadataAndRedactsErrors(t *testing.T) {
	cases := []string{
		`{"accountId":"other","accountGeneration":"1","sequence":1}`,
		`{"accountId":"acct","accountGeneration":"2","sequence":1}`,
		`{"accountId":"acct","accountGeneration":"1","sequence":0}`,
		`{"accountId":"acct","accountGeneration":"1","sequence":1,"secret":"synthetic_secret"}`,
		`{"accountId":"acct","accountGeneration":"1","sequence":1,"sequence":2}`,
		`{"accountId":"acct","accountGeneration":"1","sequence":1.5}`,
		`{"accountId":"acct","accountGeneration":"1","sequence":null}`,
		`{"accountId":"acct","accountGeneration":"1","sequence":"1"}`,
		`{"accountId":"acct","accountGeneration":"1","sequence":9007199254740992}`,
		`{"accountId":"acct","accountGeneration":"1","sequence":1} {}`,
		strings.Repeat("synthetic_secret", 100),
	}
	for i, data := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := newNotificationFixture(t)
			sub, err := f.client.OpenNotifications(context.Background())
			check(t, err)
			defer sub.Close()
			conn := f.next(t)
			_, err = sub.Read(context.Background())
			check(t, err)
			_ = conn.Write(context.Background(), websocket.MessageText, []byte(data))
			_, err = sub.Read(context.Background())
			if err == nil || strings.Contains(err.Error(), "synthetic_secret") {
				t.Fatal("非法通知未拒绝或泄露正文")
			}
		})
	}
	f := newNotificationFixture(t)
	f.rejectHandshake = true
	_, err := f.client.OpenNotifications(context.Background())
	if err == nil || strings.Contains(err.Error(), "synthetic_secret") {
		t.Fatal("握手错误泄露正文")
	}
}
func TestNotificationDuplicateCoalescingCancellationAndEpoch(t *testing.T) {
	f := newNotificationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	sub, err := f.client.OpenNotifications(ctx)
	check(t, err)
	conn := f.next(t)
	seen := make(chan uint64, 8)
	done := make(chan error, 1)
	go func() { done <- sub.Watch(ctx, func(h NotificationHint) { seen <- h.Sequence }) }()
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("未收到首提示")
	}
	f.hint(t, conn, 1)
	f.hint(t, conn, 2)
	select {
	case n := <-seen:
		if n != 2 {
			t.Fatal("重复提示未合并")
		}
	case <-time.After(time.Second):
		t.Fatal("未收到新提示")
	}
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("断开未取消读取/心跳")
	}
	sub, err = f.client.OpenNotifications(context.Background())
	check(t, err)
	defer sub.Close()
	f.next(t)
	check(t, f.engine.LogoutAtEpoch(f.engine.State().SessionEpoch))
	_, err = sub.Read(context.Background())
	if !errors.Is(err, localstate.ErrLocalSession) {
		t.Fatal("旧epoch提示未被拒绝", err)
	}
}
