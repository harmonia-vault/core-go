//go:build windows

package main

import (
	"context"
	"errors"
	"golang.org/x/sys/windows/svc"
	"time"
)

// 此handler仅用于专用own-process同步服务，run返回前必须完成全部drain与Store.Close。
// 不使用旧10秒提前结束逻辑；慢清理保持StopPending且继续固定配置/映像句柄。
type windowsOwnerHandler struct {
	parent context.Context
	run    func(context.Context, func()) error
}

func (h windowsOwnerHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.parent)
	defer cancel()
	status <- svc.Status{State: svc.StartPending, WaitHint: 30000}
	done := make(chan error, 1)
	ready := make(chan struct{})
	go func() { done <- h.run(ctx, func() { close(ready) }) }()
	running := false
	stopping := false
	checkpoint := uint32(0)
	parentDone := h.parent.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	publishStop := func() {
		checkpoint++
		status <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: 30000}
	}
	stop := func() {
		if !stopping {
			stopping = true
			cancel()
			publishStop()
		}
	}
	for {
		select {
		case <-ready:
			ready = nil
			if !stopping {
				running = true
				status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		case err := <-done:
			if err != nil {
				return true, ownerServiceFailureCode(err)
			}
			return false, 0
		case <-parentDone:
			parentDone = nil
			stop()
		case request, ok := <-requests:
			if !ok {
				requests = nil
				stop()
				continue
			}
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				stop()
			case svc.Interrogate:
				if stopping {
					publishStop()
				} else {
					status <- request.CurrentStatus
				}
			}
		case <-ticker.C:
			if stopping {
				publishStop()
			} else if !running {
				checkpoint++
				status <- svc.Status{State: svc.StartPending, CheckPoint: checkpoint, WaitHint: 30000}
			}
		}
	}
}

// StartServiceCtrlDispatcher itself rejects interactive launches. The complete
// own-service/token/configuration verification executes inside this handler,
// before any key or IPC/network initialization, so rejection reaches SCM status.
func runWindowsAccountService(ctx context.Context, name string, run func(context.Context, func()) error) error {
	return svc.Run(name, windowsOwnerHandler{parent: ctx, run: run})
}
func runWindowsOwnerService(ctx context.Context, name string, run func(context.Context, func()) error) error {
	isService, e := svc.IsWindowsService()
	if e != nil {
		return e
	}
	if !isService {
		return errors.New("同步owner只能由Windows SCM启动")
	}
	return svc.Run(name, windowsOwnerHandler{parent: ctx, run: run})
}
