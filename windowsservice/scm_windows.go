//go:build windows

package windowsservice

import (
	"context"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"time"
	"unsafe"
)

type brokerHandler struct {
	parent context.Context
	locked *LockedConfig
}

func (h brokerHandler) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.parent)
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- runBroker(ctx, h.locked, func() { close(ready) }) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	checkpoint := uint32(1)
	running := false
	stopping := false
	var deadline <-chan time.Time
	publish := func() {
		state := svc.StartPending
		accepts := svc.Accepted(0)
		if running {
			state = svc.Running
			accepts = svc.AcceptStop | svc.AcceptShutdown
		}
		if stopping {
			state = svc.StopPending
			accepts = 0
		}
		point := checkpoint
		hint := uint32(30000)
		if running && !stopping {
			point = 0
			hint = 0
		}
		status <- svc.Status{State: state, Accepts: accepts, CheckPoint: point, WaitHint: hint}
	}
	publish()
	parentDone := h.parent.Done()
	stop := func() {
		if !stopping {
			stopping = true
			cancel()
			deadline = time.After(30 * time.Second)
			publish()
		}
	}
	for {
		select {
		case <-ready:
			running = true
			ready = nil
			publish()
		case e := <-done:
			if e == ErrCleanup {
				stop()
				// 未确认 Unload/Close 成功时只能终止本专用服务进程；失败则永不报告 Stopped。
				e = h.failDrain(nil, ticker.C, func() { checkpoint++; publish() })
			}
			if e != nil && e != context.Canceled {
				return true, 1
			}
			return false, 0
		case <-parentDone:
			stop()
			parentDone = nil
		case r, ok := <-requests:
			if !ok {
				stop()
				requests = nil
				continue
			}
			switch r.Cmd {
			case svc.Interrogate:
				publish()
			case svc.Stop, svc.Shutdown:
				stop()
			}
		case <-ticker.C:
			if !running || stopping {
				checkpoint++
				publish()
			}
		case <-deadline:
			// TerminateProcess(self) 成功不会返回；失败则继续等待所有 worker/lease 完成。
			e := h.failDrain(done, ticker.C, func() { checkpoint++; publish() })
			if e != nil && e != context.Canceled {
				return true, 2
			}
			return false, 0
		}
	}
}

// RunSCMBroker 接受 SCM 启动，不在普通 CLI 中安装服务或提升 token。
func RunSCMBroker(ctx context.Context, configPath string) error {
	service, e := svc.IsWindowsService()
	if e != nil || !service {
		return ErrIdentity
	}
	locked, e := LoadConfig(configPath)
	if e != nil {
		return e
	}
	defer locked.Close()
	if requireSYSTEM(locked.Config, true) != nil || !ownProcessBroker(locked.Config) {
		return ErrIdentity
	}
	return svc.Run(locked.Config.BrokerServiceName(), brokerHandler{parent: ctx, locked: locked})
}

// 仅用于 SERVICE_WIN32_OWN_PROCESS 专用 broker，不能嵌入共享宿主服务进程。
func (h brokerHandler) failDrain(done <-chan error, ticks <-chan time.Time, heartbeat func()) error {
	return drainFailure(done, ticks, func() { _ = windows.TerminateProcess(windows.CurrentProcess(), 2) }, heartbeat)
}

// fatal stop 策略只可用于实际 SCM OWN_PROCESS；拒绝配置成共享宿主服务。
func ownProcessBroker(c Config) bool {
	manager, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return false
	}
	defer windows.CloseServiceHandle(manager)
	service, e := windows.OpenService(manager, windows.StringToUTF16Ptr(c.BrokerServiceName()), windows.SERVICE_QUERY_CONFIG)
	if e != nil {
		return false
	}
	defer windows.CloseServiceHandle(service)
	var needed uint32
	_ = windows.QueryServiceConfig(service, nil, 0, &needed)
	if needed < uint32(unsafe.Sizeof(windows.QUERY_SERVICE_CONFIG{})) || needed > 16384 {
		return false
	}
	data := make([]byte, needed)
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&data[0]))
	if windows.QueryServiceConfig(service, cfg, needed, &needed) != nil {
		return false
	}
	return cfg.ServiceType == windows.SERVICE_WIN32_OWN_PROCESS
}
