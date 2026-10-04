//go:build windows

package main

import (
	"context"
	"errors"
	"golang.org/x/sys/windows/svc"
	"testing"
	"time"
)

func TestWindowsOwnerSCMWaitsDrainAndReportsCleanupFailure(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	draining := make(chan struct{})
	release := make(chan struct{})
	statuses := make(chan svc.Status, 8)
	requests := make(chan svc.ChangeRequest)
	h := windowsOwnerHandler{parent: parent, run: func(ctx context.Context, ready func()) error {
		ready()
		<-ctx.Done()
		close(draining)
		<-release
		return errors.New("synthetic cleanup failure")
	}}
	type outcome struct {
		failed bool
		code   uint32
	}
	done := make(chan outcome, 1)
	go func() { failed, code := h.Execute(nil, requests, statuses); done <- outcome{failed, code} }()
	for {
		s := <-statuses
		if s.State == svc.Running {
			break
		}
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	<-draining
	select {
	case <-done:
		t.Fatal("清理尚未完成即SCM结束")
	default:
	}
	select {
	case s := <-statuses:
		if s.State != svc.StopPending || s.CheckPoint == 0 {
			t.Fatal("未发布真实StopPending")
		}
	case <-time.After(time.Second):
		t.Fatal("没有停服进度")
	}
	close(release)
	select {
	case got := <-done:
		if !got.failed || got.code == 0 {
			t.Fatal("吞掉真实清理失败")
		}
	case <-time.After(time.Second):
		t.Fatal("完成清理后仍未返回")
	}
}
