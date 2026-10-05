package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/harmonia-vault/core-go/accountreset"
)

var errResetLocal = errors.New("account reset native cleanup unconfirmed")

// NativeAccountResetCleanup 只能由持固定槽锁的可信原生实现，不能由 Dart 实现。
// ClearAndReacquireEmpty 必须验证匹配账号、完成 Logout/真实删除/Close/释放，
// 再持新 owner 证明所有固定 system/PIN 对象缺席；新手机同样要有真实空槽证据。
// 新 owner 必须持续持有直到 Complete 返回并排空；CheckEmpty 逐次核验完整快照。
type NativeAccountResetCleanup interface {
	ClearAndReacquireEmpty() error
	CheckEmpty() error
}

type resetAttempt interface {
	Query(context.Context) (accountreset.Outcome, error)
	Submit(context.Context) (accountreset.Outcome, error)
	Close()
}

// NativeAccountReset 是原生 RAM owner。没有序列化/从旧 proof 重建 retry 的入口。
// namespace 和 CA 由平台固定构造，实例及完成票都不跨 MethodChannel。
type NativeAccountReset struct {
	mu                  sync.Mutex
	endpoint, namespace string
	proof               accountreset.Proof
	query               func(context.Context, accountreset.Proof) (accountreset.Outcome, error)
	prepare             func(accountreset.Proof, []byte, string) (resetAttempt, error)
	attempt             resetAttempt
	verified            bool
	queryOnly           bool
	running, closed     bool
	cancel              context.CancelFunc
	pending             *NativeAccountResetCommit
	now                 func() time.Time
}

// OpenNativeAccountResetQuery 用于原 RAM 丢失后的查询，永久禁止 Prepare/Submit。
func OpenNativeAccountResetQuery(endpoint, namespace string, proof, additionalCA []byte) (*NativeAccountReset, error) {
	r, err := NewNativeAccountReset(endpoint, namespace, proof, additionalCA)
	if err != nil {
		return nil, err
	}
	r.queryOnly = true
	return r, nil
}

func (*NativeAccountReset) String() string       { return "native account reset owner (opaque)" }
func (*NativeAccountResetCommit) String() string { return "native account reset completion (opaque)" }

// NewNativeAccountReset 只消费邮箱和八位字母数字码；内部凭证仅从服务器换取。
func NewNativeAccountReset(endpoint, namespace string, proof, additionalCA []byte) (*NativeAccountReset, error) {
	defer clear(proof)
	canonical, err := validateEndpoint(endpoint)
	if err != nil || canonical != endpoint || namespace == "" || len(namespace) > 512 {
		return nil, errInput
	}
	h, err := workflowHTTPClient(additionalCA)
	if err != nil {
		return nil, errInput
	}
	c, err := accountreset.New(accountreset.Config{Endpoint: endpoint, HTTPClient: h})
	if err != nil {
		return nil, errInput
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p, err := c.ResolveCode(ctx, proof)
	if err != nil {
		if code := emailCodeFailure(err); code != "" {
			return nil, errors.New(code)
		}
		return nil, err
	}
	return &NativeAccountReset{endpoint: endpoint, namespace: namespace, proof: p, query: c.Query,
		prepare: func(p accountreset.Proof, b []byte, s string) (resetAttempt, error) { return c.NewAttempt(p, b, s) }, now: time.Now}, nil
}

func (r *NativeAccountReset) start() (context.Context, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, accountreset.ErrClosed
	}
	if r.running || r.pending != nil {
		return nil, accountreset.ErrBusy
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel, r.running = cancel, true
	return ctx, nil
}
func (r *NativeAccountReset) finish() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.running = false
	return !r.closed
}
func resetOutcomeJSON(out accountreset.Outcome) (string, error) {
	b, e := json.Marshal(struct {
		Version       int                  `json:"version"`
		TrustedDevice bool                 `json:"trustedDevice"`
		Outcome       accountreset.Outcome `json:"outcome"`
	}{1, false, out})
	return string(b), e
}
func (r *NativeAccountReset) runQuery(ctx context.Context) (accountreset.Outcome, error) {
	r.mu.Lock()
	a, p, q := r.attempt, r.proof, r.query
	r.mu.Unlock()
	if a != nil {
		return a.Query(ctx)
	}
	return q(ctx, p)
}

// Query 从不清理或提交；无原 Attempt 的冷启动只能使用此元数据路径。
func (r *NativeAccountReset) Query() (string, error) {
	ctx, e := r.start()
	if e != nil {
		return "", e
	}
	out, e := r.runQuery(ctx)
	r.mu.Lock()
	r.verified = !r.closed && e == nil && out.State == "pending"
	r.mu.Unlock()
	if !r.finish() {
		return "", accountreset.ErrClosed
	}
	if e != nil {
		return "", e
	}
	return resetOutcomeJSON(out)
}

// Prepare 只创建一次原 payload；只用于本次明确开始的新重置，不是冷恢复入口。
// 原生不得将丢失 owner 的 resume 请求路由到本方法。重试方法没有替代输入。
func (r *NativeAccountReset) Prepare(password []byte, confirmation string) error {
	defer clear(password)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return accountreset.ErrClosed
	}
	if r.running || r.pending != nil {
		return accountreset.ErrBusy
	}
	if r.queryOnly || !r.verified || r.attempt != nil {
		return errInput
	}
	a, e := r.prepare(r.proof, password, confirmation)
	if e != nil {
		return e
	}
	r.attempt = a
	return nil
}

// NativeAccountResetCommit 仅由一次成功的原 proof Query 签发，短时、单次、同 RAM owner。
// 这是原生控制对象，不是云授权、设备信任或可持久化票据。
type NativeAccountResetCommit struct {
	owner              *NativeAccountReset
	out                accountreset.Outcome
	expires            time.Time
	consumed, cleaning bool // 均由 owner.mu 保护
}

// BeginCompletion 每次明确提交/重试前重新 Query；验证前不调用任何本机清理。
func (r *NativeAccountReset) BeginCompletion() (*NativeAccountResetCommit, error) {
	ctx, e := r.start()
	if e != nil {
		return nil, e
	}
	r.mu.Lock()
	a := r.attempt
	r.mu.Unlock()
	if a == nil {
		r.finish()
		return nil, errInput
	}
	out, e := a.Query(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.running = false
	if r.closed {
		return nil, accountreset.ErrClosed
	}
	if e != nil {
		return nil, e
	}
	if out.State != "pending" && out.State != "complete" {
		return nil, accountreset.ErrResponse
	}
	p := &NativeAccountResetCommit{owner: r, out: out, expires: r.now().Add(120 * time.Second)}
	r.pending = p
	return p, nil
}

// LogoutMatchedWorkflow 只能在当前 cleanup 回调内调用。账号来源必须是此前
// AEAD 解密验证的 private binding；不使用 View/云信任，也不接受 caller 账号声明。
func (p *NativeAccountResetCommit) LogoutMatchedWorkflow(v *VaultWorkflow) error {
	if p == nil || p.owner == nil || v == nil {
		return errInput
	}
	r := p.owner
	r.mu.Lock()
	allowed := !r.closed && r.pending == p && p.cleaning && r.now().Before(p.expires)
	endpoint, namespace, proof := r.endpoint, r.namespace, r.proof
	r.mu.Unlock()
	if !allowed {
		return accountreset.ErrClosed
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	r.mu.Lock()
	allowed = !r.closed && r.pending == p && p.cleaning && r.now().Before(p.expires)
	r.mu.Unlock()
	if !allowed {
		return accountreset.ErrClosed
	}
	if v.workflow == nil || len(v.key) == 0 || len(v.lastSealed) == 0 || v.binding.Endpoint != endpoint || v.binding.Namespace != namespace || v.binding.AccountID != proof.AccountID || v.binding.AccountGeneration != proof.AccountGeneration {
		return errResetLocal
	}
	if e := v.checkProtected(v.protectedSHA256); e != nil {
		return errResetLocal
	}
	v.deleteDevice = true
	if e := v.workflow.Logout(); e != nil {
		return errResetLocal
	}
	return nil
}

func (p *NativeAccountResetCommit) Complete(local NativeAccountResetCleanup) (string, error) {
	if p == nil || p.owner == nil || local == nil {
		return "", errInput
	}
	r := p.owner
	r.mu.Lock()
	if r.closed || r.pending != p || p.consumed || !r.now().Before(p.expires) {
		r.mu.Unlock()
		return "", accountreset.ErrClosed
	}
	p.consumed, p.cleaning = true, true
	r.running = true
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	a := r.attempt
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		p.cleaning = false
		if r.pending == p {
			r.pending = nil
		}
		r.mu.Unlock()
		r.finish()
	}()
	if e := local.ClearAndReacquireEmpty(); e != nil {
		return "", errResetLocal
	}
	r.mu.Lock()
	p.cleaning = false
	allowed := !r.closed && r.now().Before(p.expires)
	r.mu.Unlock()
	if !allowed || ctx.Err() != nil {
		return "", accountreset.ErrClosed
	}
	if e := local.CheckEmpty(); e != nil {
		return "", errResetLocal
	}
	out := p.out
	if out.State == "pending" {
		var e error
		out, e = a.Submit(ctx)
		if e != nil {
			return "", e
		}
	}
	if e := local.CheckEmpty(); e != nil {
		return "", errResetLocal
	}
	r.mu.Lock()
	allowed = !r.closed && r.now().Before(p.expires)
	r.mu.Unlock()
	if !allowed || ctx.Err() != nil {
		return "", accountreset.ErrClosed
	}
	return resetOutcomeJSON(out)
}

// Close 取消尚未消费的票，不提交。运行中的完成必须由整个 RAM owner Close 取消。
func (p *NativeAccountResetCommit) Close() {
	if p == nil || p.owner == nil {
		return
	}
	r := p.owner
	r.mu.Lock()
	defer r.mu.Unlock()
	if !p.consumed && r.pending == p {
		p.consumed = true
		r.pending = nil
	}
}

// Close 先退休/取消，网络与原生清理均不在此互斥锁内等待。平台仍须排空 worker。
func (r *NativeAccountReset) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.verified = false
	a, cancel := r.attempt, r.cancel
	r.proof = accountreset.Proof{}
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if a != nil {
		a.Close()
	}
}
