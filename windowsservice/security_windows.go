//go:build windows

package windowsservice

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var impersonatePipe = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
var getLogonData = windows.NewLazySystemDLL("secur32.dll").NewProc("LsaGetLogonSessionData")
var freeLogonData = windows.NewLazySystemDLL("secur32.dll").NewProc("LsaFreeReturnBuffer")

type tokenStats struct {
	TokenID          windows.LUID
	AuthenticationID windows.LUID
	Expiration       int64
	TokenType        uint32
	Level            uint32
	DynamicCharged   uint32
	DynamicAvailable uint32
	GroupCount       uint32
	PrivilegeCount   uint32
	ModifiedID       windows.LUID
}
type lsaString struct {
	Length  uint16
	Maximum uint16
	Buffer  *uint16
}

// 只读官方 SECURITY_LOGON_SESSION_DATA 前缀，不读取用户名/域/登录秘密。
type logonDataPrefix struct {
	Size     uint32
	LogonID  windows.LUID
	UserName lsaString
	Domain   lsaString
	Package  lsaString
	Type     uint32
	Session  uint32
	SID      *windows.SID
}

func pipeHandle(conn net.Conn) (windows.Handle, error) {
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, ErrIdentity
	}
	return windows.Handle(fd.Fd()), nil
}
func tokenUser(token windows.Token, expected string) bool {
	u, e := token.GetTokenUser()
	return e == nil && u.User.Sid != nil && u.User.Sid.String() == expected
}
func enabledGroup(token windows.Token, expected string) bool {
	g, e := token.GetTokenGroups()
	if e != nil {
		return false
	}
	for _, item := range g.AllGroups() {
		if item.Sid.String() == expected && item.Attributes&windows.SE_GROUP_ENABLED != 0 && item.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return true
		}
	}
	return false
}
func tokenLevel(token windows.Token) (uint32, error) {
	var kind, level, size uint32
	if windows.GetTokenInformation(token, windows.TokenType, (*byte)(unsafe.Pointer(&kind)), 4, &size) != nil || kind != windows.TokenImpersonation {
		return 0, ErrIdentity
	}
	if windows.GetTokenInformation(token, windows.TokenImpersonationLevel, (*byte)(unsafe.Pointer(&level)), 4, &size) != nil {
		return 0, ErrIdentity
	}
	return level, nil
}
func batchToken(token windows.Token, c Config) bool {
	var stats tokenStats
	var size uint32
	if windows.GetTokenInformation(token, windows.TokenStatistics, (*byte)(unsafe.Pointer(&stats)), uint32(unsafe.Sizeof(stats)), &size) != nil || size != uint32(unsafe.Sizeof(stats)) {
		return false
	}
	var data *logonDataPrefix
	status, _, _ := getLogonData.Call(uintptr(unsafe.Pointer(&stats.AuthenticationID)), uintptr(unsafe.Pointer(&data)))
	if status != 0 || data == nil {
		return false
	}
	defer freeLogonData.Call(uintptr(unsafe.Pointer(data)))
	// Batch=4；只接受 Session 0 的 exact 本地目标 SID，不回退已交互登录 token。
	return data.Size >= uint32(unsafe.Sizeof(logonDataPrefix{})) && data.Type == 4 && data.Session == 0 && data.SID != nil && data.SID.String() == c.TargetSID
}
func processPeer(conn net.Conn, c Config, server bool, expected string, broker bool) (windows.Handle, windows.Token, error) {
	expectedImage := c.Executable
	if !server && expected == c.SyncServiceSID {
		expectedImage = c.SyncExecutable
	}
	return processPeerImage(conn, c, server, expected, expectedImage, broker)
}
func processPeerImage(conn net.Conn, c Config, server bool, expected, expectedImage string, broker bool) (windows.Handle, windows.Token, error) {
	h, e := pipeHandle(conn)
	if e != nil {
		return 0, 0, e
	}
	var pid uint32
	if server {
		e = windows.GetNamedPipeServerProcessId(h, &pid)
	} else {
		e = windows.GetNamedPipeClientProcessId(h, &pid)
	}
	if e != nil || pid == 0 {
		return 0, 0, ErrIdentity
	}
	proc, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return 0, 0, ErrIdentity
	}
	var token windows.Token
	good := false
	defer func() {
		if !good {
			if token != 0 {
				_ = token.Close()
			}
			_ = windows.CloseHandle(proc)
		}
	}()
	if windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token) != nil || !tokenUser(token, expected) {
		return 0, 0, ErrIdentity
	}
	if broker && !enabledGroup(token, c.BrokerServiceSID) {
		return 0, 0, ErrIdentity
	}
	var image [32768]uint16
	size := uint32(len(image))
	if windows.QueryFullProcessImageName(proc, 0, &image[0], &size) != nil || !strings.EqualFold(windows.UTF16ToString(image[:size]), expectedImage) {
		return 0, 0, ErrIdentity
	}
	good = true
	return proc, token, nil
}

// readFrame 必须已读取 hello/request，确保 impersonation 绑定的是最后读到的该消息。
// 此函数持有 peer process handle，比较 process 与 thread token，恢复成功才返回。
func authenticatedClient(conn net.Conn, c Config, expected string, wantUserToken bool) (windows.Token, error) {
	proc, processToken, e := processPeer(conn, c, false, expected, false)
	if e != nil {
		return 0, e
	}
	defer windows.CloseHandle(proc)
	defer processToken.Close()
	if wantUserToken && !batchToken(processToken, c) {
		return 0, ErrIdentity
	}
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
		return 0, e
	}
	result, _, _ := impersonatePipe.Call(uintptr(h))
	if result == 0 {
		runtime.UnlockOSThread()
		return 0, ErrIdentity
	}
	var thread windows.Token
	var duplicate windows.Token
	e = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, true, &thread)
	if e == nil {
		level, le := tokenLevel(thread)
		minimum := uint32(windows.SecurityIdentification)
		if wantUserToken {
			minimum = uint32(windows.SecurityImpersonation)
		}
		if le != nil || level < minimum || !tokenUser(thread, expected) || (wantUserToken && !batchToken(thread, c)) {
			e = ErrIdentity
		}
		if e == nil && wantUserToken {
			e = windows.DuplicateTokenEx(thread, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenPrimary, &duplicate)
		}
		_ = thread.Close()
	}
	// 不能让失败的 revert 线程回到 Go 线程池。调用方遇错误立即退出当前 handler goroutine。
	if re := windows.RevertToSelf(); re != nil {
		if duplicate != 0 {
			_ = duplicate.Close()
		}
		return 0, ErrIdentity
	}
	reverted = true
	if e != nil {
		if duplicate != 0 {
			_ = duplicate.Close()
		}
		return 0, ErrIdentity
	}
	if wantUserToken && (!tokenUser(duplicate, expected) || !batchToken(duplicate, c)) {
		_ = duplicate.Close()
		return 0, ErrIdentity
	}
	return duplicate, nil
}
func requireSYSTEM(c Config, asService bool) error {
	token := windows.GetCurrentProcessToken()
	if !tokenUser(token, "S-1-5-18") || (asService && !enabledGroup(token, c.BrokerServiceSID)) {
		return ErrIdentity
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var thread windows.Token
	e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &thread)
	if e == nil {
		_ = thread.Close()
		return ErrIdentity
	}
	if !errors.Is(e, windows.ERROR_NO_TOKEN) {
		return ErrIdentity
	}
	return nil
}
func nativeClientIdentity(c Config) error {
	if !tokenUser(windows.GetCurrentProcessToken(), c.SyncServiceSID) {
		return ErrIdentity
	}
	locked, e := LoadConfig(c.ConfigurationFile)
	if e != nil {
		return e
	}
	defer locked.Close()
	if locked.Config != c {
		return ErrConfiguration
	}
	return nil
}
func nativeServerIdentity(conn net.Conn, c Config) error {
	proc, token, e := processPeer(conn, c, true, "S-1-5-18", true)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(proc)
	defer token.Close()
	return nil
}
