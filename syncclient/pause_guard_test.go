package syncclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localstate"
)

// 在真实HTTPS响应返回且完整验证已经结束之后阻塞，用于确定地测试应用事务
// 与pause的竞争。它不替代密码学验证，也不引入生产信任旁路。
type beforeApplyVerifier struct {
	pinned  *PinnedVerifier
	entered chan struct{}
	resume  chan struct{}
}

func (v *beforeApplyVerifier) VerifyPull(ctx context.Context, pull Pull, previous localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	out, err := v.pinned.VerifyPull(ctx, pull, previous)
	close(v.entered)
	select {
	case <-v.resume:
	case <-ctx.Done():
		return localstate.CloudSnapshot{}, ctx.Err()
	}
	return out, err
}
func (v *beforeApplyVerifier) VerifyAuthorizationRefresh(ctx context.Context, pull Pull, previous localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	return v.pinned.VerifyAuthorizationRefresh(ctx, pull, previous)
}

func TestInFlightPullPausedAfterVerificationDoesNotApplyData(t *testing.T) {
	f := newNotificationFixture(t)
	_, err := f.client.Pull(context.Background())
	check(t, err)
	f.mu.Lock()
	f.sequence = 2
	f.events = append(f.events, f.crypto.event(t, 2, "late-ordinary-synthetic"))
	f.mu.Unlock()
	v := &beforeApplyVerifier{pinned: f.crypto.verifier, entered: make(chan struct{}), resume: make(chan struct{})}
	config := f.client.config
	config.Verifier = v
	client, err := New(config)
	check(t, err)
	done := make(chan error, 1)
	go func() { _, e := client.Pull(context.Background()); done <- e }()
	select {
	case <-v.entered:
	case <-time.After(time.Second):
		t.Fatal("普通响应没有进入验签后的在途边界")
	}
	check(t, f.engine.SetPaused(true))
	close(v.resume)
	if err = <-done; !errors.Is(err, ErrPaused) {
		t.Fatal("暂停竞争没有拒绝普通值", err)
	}
	state := f.engine.State()
	if state.Cloud.Sequence != 1 || state.Cloud.AuthorizationSequence != 2 || state.Cloud.Environments["env"].Values["TOKEN"] != "initial-synthetic" || len(state.Cloud.SeenMutations) != 1 {
		t.Fatal("迟到数据或检查点被应用")
	}
	check(t, f.engine.SetPaused(false))
	// 后续使用真实Verifier；Auth领先会强制after0完整补漏，而不是漏掉迟到值。
	_, err = f.client.Pull(context.Background())
	check(t, err)
	if f.engine.State().Cloud.Sequence != 2 || f.engine.State().Cloud.Environments["env"].Values["TOKEN"] != "late-ordinary-synthetic" {
		t.Fatal("恢复后未全量补漏")
	}
}
func TestInFlightPauseStillProcessesSignedRevocationAndRejectsForgery(t *testing.T) {
	for _, forged := range []bool{false, true} {
		t.Run(map[bool]string{false: "signed", true: "forged"}[forged], func(t *testing.T) {
			f := newNotificationFixture(t)
			_, err := f.client.Pull(context.Background())
			check(t, err)
			check(t, f.engine.Activate("env", 1, fixedNow))
			check(t, f.engine.SetOverride("env", "TOKEN", "local-only-synthetic", fixedNow))
			revoked := f.crypto.grant.Grant
			revoked.Role = "none"
			revoked.Envelope = ""
			revoked.GrantGeneration = "2"
			revoked.IdempotencyKey = "late-revoke"
			grant := f.crypto.resignGrant(t, revoked)
			if forged {
				grant.Signature = f.crypto.grant.Signature
			}
			f.mu.Lock()
			f.crypto.grant = grant
			f.sequence = 2
			f.events = nil
			f.mu.Unlock()
			v := &beforeApplyVerifier{pinned: f.crypto.verifier, entered: make(chan struct{}), resume: make(chan struct{})}
			config := f.client.config
			config.Verifier = v
			client, err := New(config)
			check(t, err)
			done := make(chan error, 1)
			go func() { _, e := client.Pull(context.Background()); done <- e }()
			select {
			case <-v.entered:
			case <-time.After(time.Second):
				t.Fatal("响应未进入在途边界")
			}
			check(t, f.engine.SetPaused(true))
			close(v.resume)
			if err = <-done; !errors.Is(err, ErrPaused) {
				t.Fatal("暂停竞态错误", err)
			}
			state := f.engine.State()
			if state.Cloud.Sequence != 1 {
				t.Fatal("暂停推进了数据序号")
			}
			if forged {
				if len(state.Cloud.Environments) != 1 || state.Cloud.AuthorizationSequence != 1 {
					t.Fatal("伪造授权被投影接受")
				}
			} else {
				if len(state.Cloud.Environments) != 0 || len(state.Overrides) != 0 || state.Cloud.AuthorizationSequence != 2 {
					t.Fatal("迟到但有效的撤销没有执行")
				}
			}
		})
	}
}
