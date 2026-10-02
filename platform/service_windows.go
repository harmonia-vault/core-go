//go:build windows

package platform

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
)

type windowsHandler struct {
	parent context.Context
	run    func(context.Context) error
}

func (h windowsHandler) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.parent)
	defer cancel()
	status <- svc.Status{State: svc.StartPending}
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		case <-h.parent.Done():
			cancel()
			return h.stop(done, status)
		case request, ok := <-requests:
			if !ok {
				cancel()
				return h.stop(done, status)
			}
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancel()
				return h.stop(done, status)
			}
		}
	}
}
func (h windowsHandler) stop(done <-chan error, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StopPending, WaitHint: 10000}
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			return true, 1
		}
		return false, 0
	case <-time.After(10 * time.Second):
		return true, 2
	}
}

// RunWindowsService 接入 SCM 生命周期；run 必须遵守 ctx 取消，不执行安装或提权。
func RunWindowsService(ctx context.Context, name string, run func(context.Context) error) error {
	if !serviceNamePattern.MatchString(name) || run == nil {
		return fmt.Errorf("invalid service configuration")
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return fmt.Errorf("not started by Windows Service Control Manager")
	}
	return svc.Run(name, windowsHandler{parent: ctx, run: run})
}
