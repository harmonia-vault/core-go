//go:build windows

package localipc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// 目标用户仅读写数据、查询属性与同步；不授予创建其它 pipe 实例的权限。
const clientPipeAccess = windows.READ_CONTROL | windows.SYNCHRONIZE | windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES

func windowsEndpoint(endpoint Endpoint) (string, error) {
	if !filepath.IsAbs(endpoint.Directory) || filepath.Clean(endpoint.Directory) != endpoint.Directory || strings.ContainsAny(endpoint.Directory, "\x00\r\n") || endpoint.ServiceSID == "" {
		return "", ErrIdentity
	}
	for _, value := range []string{endpoint.UserID, endpoint.ServiceSID} {
		sid, err := windows.StringToSid(value)
		if err != nil || sid.String() != value {
			return "", ErrIdentity
		}
	}
	if !strings.HasPrefix(endpoint.UserID, "S-1-5-21-") {
		return "", ErrIdentity
	}
	sum := sha256.Sum256([]byte(endpoint.UserID + "\x00" + endpoint.ServiceSID + "\x00" + strings.ToUpper(endpoint.Directory)))
	return `\\.\pipe\harmonia-` + hex.EncodeToString(sum[:16]), nil
}
func tokenHasSID(token windows.Token, expected string, groupsAllowed bool) bool {
	user, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	if user.User.Sid.String() == expected {
		return true
	}
	if !groupsAllowed {
		return false
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.String() == expected && group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return true
		}
	}
	return false
}
func currentIdentity(expected string, groupsAllowed bool) bool {
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token) != nil {
		return false
	}
	defer token.Close()
	return tokenHasSID(token, expected, groupsAllowed)
}
func listenNative(endpoint Endpoint) (nativeListener, error) {
	name, err := windowsEndpoint(endpoint)
	if err != nil {
		return nativeListener{}, err
	}
	if !currentIdentity(endpoint.ServiceSID, true) {
		return nativeListener{}, ErrIdentity
	}
	descriptor := "D:P(A;;0x00120083;;;" + endpoint.UserID + ")(A;;GA;;;" + endpoint.ServiceSID + ")"
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: descriptor, MessageMode: false, InputBufferSize: 65536, OutputBufferSize: 65536})
	if err != nil {
		return nativeListener{}, ErrUnavailable
	}
	return nativeListener{Listener: listener}, nil
}
func dialNative(ctx context.Context, endpoint Endpoint) (net.Conn, error) {
	name, err := windowsEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if !currentIdentity(endpoint.UserID, false) {
		return nil, ErrIdentity
	}
	return winio.DialPipeAccessImpLevel(ctx, name, clientPipeAccess, winio.PipeImpLevelIdentification)
}
func authorizeNative(connection net.Conn, endpoint Endpoint, server bool) error {
	if _, err := windowsEndpoint(endpoint); err != nil {
		return err
	}
	return useNative(connection, func(conn net.Conn) error {
		handle, ok := conn.(interface{ Fd() uintptr })
		if !ok {
			return ErrIdentity
		}
		var pid uint32
		var err error
		if server {
			err = windows.GetNamedPipeServerProcessId(windows.Handle(handle.Fd()), &pid)
		} else {
			err = windows.GetNamedPipeClientProcessId(windows.Handle(handle.Fd()), &pid)
		}
		if err != nil || pid == 0 {
			return ErrIdentity
		}
		process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return ErrIdentity
		}
		defer windows.CloseHandle(process)
		var token windows.Token
		if windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token) != nil {
			return ErrIdentity
		}
		defer token.Close()
		expected := endpoint.UserID
		if server {
			expected = endpoint.ServiceSID
		}
		if !tokenHasSID(token, expected, server) {
			return ErrIdentity
		}
		return nil
	})
}

// CurrentUserID 返回当前进程用户 SID；没有读取或解密凭据。
func CurrentUserID() (string, error) {
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token) != nil {
		return "", ErrIdentity
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", ErrIdentity
	}
	return user.User.Sid.String(), nil
}
