package mobilebridge

import (
	"context"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/accountreset"
)

// NativeAccountResetMail 只持申请邮件的 RAM 生命周期，不持证明、账号、设备或槽。
// 平台须在固定 scope 内构造、退休并排空；不允许 Dart 提供 namespace 或 CA。
type NativeAccountResetMail struct {
	mu              sync.Mutex
	request         func(context.Context, string) error
	running, closed bool
	cancel          context.CancelFunc
}

func (*NativeAccountResetMail) String() string { return "native account reset mail owner (opaque)" }

// OpenNativeAccountResetMail 只复用既有 HTTPS 邮件请求；不授予任何设备信任。
func OpenNativeAccountResetMail(endpoint, namespace string, additionalCA []byte) (*NativeAccountResetMail, error) {
	canonical, e := validateEndpoint(endpoint)
	if e != nil || canonical != endpoint || namespace == "" || len(namespace) > 512 || !utf8.ValidString(namespace) {
		return nil, errInput
	}
	h, e := workflowHTTPClient(additionalCA)
	if e != nil {
		return nil, errInput
	}
	c, e := accountreset.New(accountreset.Config{Endpoint: endpoint, HTTPClient: h})
	if e != nil {
		return nil, errInput
	}
	return &NativeAccountResetMail{request: c.RequestProof}, nil
}

// RequestEmail 消费输入；accepted 仅说明服务器接受请求，不证明邮箱存在或送达。
// 方法没有保存邮箱或生成账号/设备/清理授权的分支。
func (r *NativeAccountResetMail) RequestEmail(email []byte) (string, error) {
	defer clear(email)
	if r == nil || len(email) == 0 || len(email) > 320 || !utf8.Valid(email) || strings.ContainsAny(string(email), "\x00\r\n") {
		return "", errInput
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return "", accountreset.ErrClosed
	}
	if r.running {
		r.mu.Unlock()
		return "", accountreset.ErrBusy
	}
	if r.request == nil {
		r.mu.Unlock()
		return "", errInput
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	request := r.request
	r.cancel, r.running = cancel, true
	r.mu.Unlock()
	e := request(ctx, string(email))
	contextError := ctx.Err()
	r.mu.Lock()
	closed := r.closed
	r.cancel, r.running = nil, false
	r.mu.Unlock()
	cancel()
	if closed {
		return "", accountreset.ErrClosed
	}
	if e != nil {
		return "", e
	}
	if contextError != nil {
		return "", accountreset.ErrTransport
	}
	return `{"version":1,"accepted":true,"trustedDevice":false}`, nil
}

// Close 先退休并取消，不持锁等待网络；平台仍须等待自己的 worker 排空。
func (r *NativeAccountResetMail) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
