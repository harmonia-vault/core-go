package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localipc"
)

func TestAccountOwnerPairSurvivesCLIAndDrainsBeforeLogout(t *testing.T) {
	service, cancel := context.WithCancel(context.Background())
	defer cancel()
	var epoch atomic.Uint64
	epoch.Store(3)
	exited := make(chan struct{})
	release := make(chan struct{})
	var activated atomic.Bool
	o := newAccountOwner(service, accountOwnerCallbacks{
		Inspect: func() (localipc.AccountState, error) { return localipc.AccountState{Phase: "logged-in"}, nil }, Epoch: epoch.Load,
		Pair: func(ctx context.Context, r localipc.AccountRequest, start uint64, p func(string, []byte)) error {
			if start != 3 {
				t.Error("任务未捕获启动epoch")
			}
			p("pair-original", []byte("12345678"))
			<-ctx.Done()
			<-release
			close(exited)
			return ctx.Err()
		}, Accepted: func() error { activated.Store(true); return nil },
	})
	cli, closeCLI := context.WithCancel(context.Background())
	state, err := o.Handle(cli, localipc.AccountRequest{Action: "pair", ApproverDeviceID: "manager", CertificateVersion: "5"})
	if err != nil || state.ShortCode != "12345678" {
		t.Fatal("未返回合成短码")
	}
	closeCLI()
	select {
	case <-exited:
		t.Fatal("关闭CLI停止了服务配对任务")
	default:
	}
	drained := make(chan struct{})
	epoch.Store(4)
	go func() { o.stopPair(); close(drained) }()
	select {
	case <-drained:
		t.Fatal("未等任务结束就drain完成")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("任务未收尾")
	}
	if activated.Load() {
		t.Fatal("旧epoch启动了worker")
	}
	o.Close()
}
func TestAccountOwnerPendingOriginalReceiptCannotCancelOrChangeID(t *testing.T) {
	var epoch atomic.Uint64
	epoch.Store(1)
	o := newAccountOwner(context.Background(), accountOwnerCallbacks{
		Epoch: epoch.Load, Inspect: func() (localipc.AccountState, error) {
			return localipc.AccountState{Phase: "pending", PairingID: "pair-original"}, nil
		},
		Pair: func(ctx context.Context, _ localipc.AccountRequest, _ uint64, _ func(string, []byte)) error {
			<-ctx.Done()
			return ctx.Err()
		}, Accepted: func() error { return nil },
	})
	defer o.Close()
	state, err := o.Handle(context.Background(), localipc.AccountRequest{Action: "pair", ApproverDeviceID: "manager", CertificateVersion: "5"})
	if err != nil || state.PairingID != "pair-original" || state.ShortCode != "" {
		t.Fatal("未知提交未恢复原ID")
	}
	_, err = o.Handle(context.Background(), localipc.AccountRequest{Action: "pair-cancel", PairingID: "pair-original"})
	if !errors.Is(err, localipc.ErrAccountPending) {
		t.Fatal("sealed pending允许取消")
	}
	_, err = o.Handle(context.Background(), localipc.AccountRequest{Action: "pair-status", PairingID: "pair-replacement"})
	if !errors.Is(err, localipc.ErrProtocol) {
		t.Fatal("读取替代ID")
	}
}
func TestAccountOwnerClosedCannotReadCredentialOrStartTask(t *testing.T) {
	var invoked atomic.Bool
	o := newAccountOwner(context.Background(), accountOwnerCallbacks{Login: func(context.Context, localipc.AccountRequest) error { invoked.Store(true); return nil }})
	o.Close()
	if _, e := o.Handle(context.Background(), localipc.AccountRequest{Action: "login", Credential: make([]byte, 32)}); !errors.Is(e, localipc.ErrAccountClosed) {
		t.Fatal("关闭owner仍接受操作")
	}
	if invoked.Load() {
		t.Fatal("关闭后调用业务")
	}
}

func TestAccountOwnerFailedBeforeCodeAllowsExplicitLogin(t *testing.T) {
	var epoch atomic.Uint64
	epoch.Store(1)
	var logged atomic.Bool
	o := newAccountOwner(context.Background(), accountOwnerCallbacks{Epoch: epoch.Load, Inspect: func() (localipc.AccountState, error) { return localipc.AccountState{Phase: "logged-in"}, nil }, Pair: func(context.Context, localipc.AccountRequest, uint64, func(string, []byte)) error {
		return localipc.ErrUnavailable
	}, Login: func(context.Context, localipc.AccountRequest) error { logged.Store(true); return nil }, Accepted: func() error { return nil }})
	defer o.Close()
	if _, err := o.Handle(context.Background(), localipc.AccountRequest{Action: "pair"}); !errors.Is(err, localipc.ErrUnavailable) {
		t.Fatal("首帧失败未返回固定错误")
	}
	o.mu.Lock()
	done := o.job.done
	o.mu.Unlock()
	<-done
	if _, err := o.Handle(context.Background(), localipc.AccountRequest{Action: "login", Credential: make([]byte, 32)}); err != nil || !logged.Load() {
		t.Fatal("失败任务阻止用户明确重新登录")
	}
}
