//go:build windows

package windowsaccount

import (
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"runtime"
	"strings"
	"unsafe"
)

type PeerLease struct {
	config  *LockedConfiguration
	process windows.Handle
	token   windows.Token
}

func (l *PeerLease) Close() error {
	var err error
	if l.token != 0 {
		err = errors.Join(err, l.token.Close())
		l.token = 0
	}
	if l.process != 0 {
		err = errors.Join(err, windows.CloseHandle(l.process))
		l.process = 0
	}
	if l.config != nil {
		err = errors.Join(err, l.config.Close())
		l.config = nil
	}
	return err
}
func fixedImage(process windows.Handle, path string) bool {
	var b [32768]uint16
	n := uint32(len(b))
	return windows.QueryFullProcessImageName(process, 0, &b[0], &n) == nil && strings.EqualFold(windows.UTF16ToString(b[:n]), path)
}
func userToken(t windows.Token, sid string) bool {
	u, e := t.GetTokenUser()
	return e == nil && u.User.Sid.String() == sid
}
func serviceGroup(t windows.Token, sid string) bool {
	g, e := t.GetTokenGroups()
	if e != nil {
		return false
	}
	for _, v := range g.AllGroups() {
		if v.Sid.String() == sid && v.Attributes&windows.SE_GROUP_ENABLED != 0 && v.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return true
		}
	}
	return false
}
func SCMProcessID(p Plan) (uint32, error) {
	manager, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return 0, ErrIdentity
	}
	defer windows.CloseServiceHandle(manager)
	service, e := windows.OpenService(manager, windows.StringToUTF16Ptr(p.Name()), windows.SERVICE_QUERY_STATUS)
	if e != nil {
		return 0, ErrIdentity
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed) != nil || status.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || status.ProcessId == 0 || (status.CurrentState != windows.SERVICE_RUNNING && status.CurrentState != windows.SERVICE_START_PENDING) {
		return 0, ErrIdentity
	}
	return status.ProcessId, nil
}

// AuthenticatePeer只核本次pipe peer与最后消息身份；没有token复制或进程创建。
func AuthenticatePeer(raw net.Conn, path string, incoming bool) (_ *PeerLease, err error) {
	cfg, e := LoadConfiguration(path)
	if e != nil {
		return nil, e
	}
	lease := &PeerLease{config: cfg}
	good := false
	defer func() {
		if !good {
			_ = lease.Close()
		}
	}()
	p := cfg.Configuration.Plan
	own := windows.GetCurrentProcessToken()
	if !userToken(own, p.TargetSID) || !fixedImage(windows.CurrentProcess(), p.BinaryPath) {
		return nil, ErrIdentity
	}
	if incoming && VerifyOwnService(p) != nil {
		return nil, ErrIdentity
	}
	fd, ok := raw.(interface{ Fd() uintptr })
	if !ok {
		return nil, ErrIdentity
	}
	h := windows.Handle(fd.Fd())
	var pid uint32
	if incoming {
		e = windows.GetNamedPipeClientProcessId(h, &pid)
	} else {
		e = windows.GetNamedPipeServerProcessId(h, &pid)
	}
	if e != nil || pid == 0 {
		return nil, ErrIdentity
	}
	lease.process, e = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return nil, ErrIdentity
	}
	if windows.OpenProcessToken(lease.process, windows.TOKEN_QUERY, &lease.token) != nil || !userToken(lease.token, p.TargetSID) || !fixedImage(lease.process, p.BinaryPath) {
		return nil, ErrIdentity
	}
	if !incoming {
		sid, e := cfg.ServiceSID()
		if e != nil || !serviceGroup(lease.token, sid) {
			return nil, ErrIdentity
		}
		actual, e := SCMProcessID(p)
		if e != nil || actual != pid {
			return nil, ErrIdentity
		}
	} else {
		// 只做identification验证；Revert失败时线程不能返回Go线程池。
		runtime.LockOSThread()
		impersonate := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
		ok, _, _ := impersonate.Call(uintptr(h))
		if ok == 0 {
			runtime.UnlockOSThread()
			return nil, ErrIdentity
		}
		valid := false
		var token windows.Token
		if windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token) == nil {
			var level uint32
			var size uint32
			valid = userToken(token, p.TargetSID) && windows.GetTokenInformation(token, windows.TokenImpersonationLevel, (*byte)(unsafe.Pointer(&level)), 4, &size) == nil && level >= uint32(windows.SecurityIdentification)
			_ = token.Close()
		}
		if windows.RevertToSelf() != nil {
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		if !valid {
			return nil, ErrIdentity
		}
	}
	good = true
	return lease, nil
}
