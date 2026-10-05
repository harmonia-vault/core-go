//go:build windows

package windowsservice

import (
	"golang.org/x/sys/windows"
	"net"
	"runtime"
	"strings"
)

// SyncPeerLease 持续固定双向 peer 的身份/映像；发送 credential 或处理该帧前不能释放。
// 不返回 token/PID 给 IPC payload，也不授予或取得 token 的 duplicate/impersonate 权限。
type SyncPeerLease struct {
	process       windows.Handle
	token         windows.Token
	configuration *LockedConfig
}

func (l *SyncPeerLease) Close() error {
	if l == nil {
		return nil
	}
	var err error
	if l.token != 0 {
		if e := l.token.Close(); e != nil {
			err = ErrUnavailable
		}
		l.token = 0
	}
	if l.process != 0 {
		if e := windows.CloseHandle(l.process); e != nil {
			err = ErrUnavailable
		}
		l.process = 0
	}
	if l.configuration != nil {
		if e := l.configuration.Close(); e != nil {
			err = ErrUnavailable
		}
		l.configuration = nil
	}
	return err
}
func ownSyncImage(c Config) bool {
	var image [32768]uint16
	size := uint32(len(image))
	return windows.QueryFullProcessImageName(windows.CurrentProcess(), 0, &image[0], &size) == nil && strings.EqualFold(windows.UTF16ToString(image[:size]), c.SyncExecutable)
}

// AuthenticateSyncPipe 不接受 IPC 身份字段。c 必须绑定管理员保护的本地配置；本函数重开并持有 pins。
// incomingClient=true: 服务必须已读完整帧，绑定该最后消息的 TargetSID thread token。
// false: 用户 CLI 必须在发送任何 credential/enrollment 材料之前验证虚拟服务 user SID。
func AuthenticateSyncPipe(conn net.Conn, c Config, incomingClient bool) (*SyncPeerLease, error) {
	locked, e := LoadConfig(c.ConfigurationFile)
	if e != nil {
		return nil, ErrConfiguration
	}
	lease := &SyncPeerLease{configuration: locked}
	good := false
	defer func() {
		if !good {
			_ = lease.Close()
		}
	}()
	if locked.Config != c || !ownSyncImage(c) {
		return nil, ErrIdentity
	}
	own, want := c.TargetSID, c.SyncServiceSID
	if incomingClient {
		own, want = c.SyncServiceSID, c.TargetSID
	}
	if !tokenUser(windows.GetCurrentProcessToken(), own) {
		return nil, ErrIdentity
	}
	lease.process, lease.token, e = processPeerImage(conn, c, !incomingClient, want, c.SyncExecutable, false)
	if e != nil {
		return nil, ErrIdentity
	}
	if incomingClient {
		runtime.LockOSThread()
		reverted := false
		defer func() {
			if reverted {
				runtime.UnlockOSThread()
			}
		}()
		h, e := pipeHandle(conn)
		if e != nil {
			runtime.UnlockOSThread()
			return nil, ErrIdentity
		}
		result, _, _ := impersonatePipe.Call(uintptr(h))
		if result == 0 {
			runtime.UnlockOSThread()
			return nil, ErrIdentity
		}
		var token windows.Token
		e = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
		if e == nil {
			level, err := tokenLevel(token)
			if err != nil || level < uint32(windows.SecurityIdentification) || !tokenUser(token, c.TargetSID) {
				e = ErrIdentity
			}
			_ = token.Close()
		}
		if windows.RevertToSelf() != nil {
			// caller 必须退出当前 handler goroutine；带 impersonation 的锁定线程不能回到池中。
			return nil, ErrSyncRevert
		}
		reverted = true
		if e != nil {
			return nil, ErrIdentity
		}
	}
	good = true
	return lease, nil
}
