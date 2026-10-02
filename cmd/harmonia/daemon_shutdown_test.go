//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/harmonia-vault/core-go/localstate"
)

type shutdownBoundaryProvider struct {
	calls  atomic.Int32
	cancel context.CancelFunc
	at     int32
	result error
}

func (p *shutdownBoundaryProvider) SetPaused(context.Context, bool) error {
	if p.calls.Add(1) == p.at {
		p.cancel()
		return p.result
	}
	return nil
}
func (p *shutdownBoundaryProvider) Snapshot(context.Context, []string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (p *shutdownBoundaryProvider) Apply(context.Context, []localstate.Change) error { return nil }

// 确定地在已选中的Reconcile路径内部取消；不能只依赖select刚好先选择Done。
func TestDaemonCancellationDuringReconcileAndRealErrors(t *testing.T) {
	persistence := errors.New("synthetic durable failure")
	for _, at := range []int32{1, 2} {
		for _, result := range []error{context.Canceled, persistence, errors.Join(context.Canceled, persistence)} {
			t.Run(map[int32]string{1: "initial", 2: "ticker"}[at]+"/"+map[bool]string{true: "cancel", false: "real-failure"}[result == context.Canceled], func(t *testing.T) {
				directory := protectedTestDirectory(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				provider := &shutdownBoundaryProvider{cancel: cancel, at: at, result: result}
				err := runWithRuntime(ctx, []string{"daemon", "--local-directory", directory, "--interval", "10ms", "--sync-interval", "1h"}, io.Discard, io.Discard, commandRuntime{provider: provider})
				if result == context.Canceled {
					if err != nil {
						t.Fatal("正常取消变成失败退出", err)
					}
				} else {
					if !errors.Is(err, persistence) {
						t.Fatal("同时取消吞掉真实provider持久失败", err)
					}
				}
				if provider.calls.Load() != at {
					t.Fatal("没有触发确定的取消边界")
				}
			})
		}
	}
}
