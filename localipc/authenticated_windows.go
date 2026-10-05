//go:build windows

package localipc

import (
	"io"
	"net"
	"path/filepath"
	"strings"

	"github.com/harmonia-vault/core-go/windowsservice"
)

// 配置来自管理员保护的固定文件；目标 SID、服务 SID 和目录不能由消息选择。
func loadWindowsEndpoint(endpoint Endpoint) (*windowsservice.LockedConfig, error) {
	if endpoint.WindowsConfigFile == "" {
		return nil, ErrIdentity
	}
	locked, err := windowsservice.LoadConfig(endpoint.WindowsConfigFile)
	if err != nil {
		return nil, ErrIdentity
	}
	c := locked.Config
	want := filepath.Join(filepath.Dir(c.ConfigurationFile), "vault-"+c.Tag(), "ipc")
	if endpoint.UserID != c.TargetSID || endpoint.ServiceSID != c.SyncServiceSID || !strings.EqualFold(endpoint.Directory, want) {
		_ = locked.Close()
		return nil, ErrIdentity
	}
	return locked, nil
}
func authenticateFrameNative(conn net.Conn, endpoint Endpoint, incoming bool) (io.Closer, error) {
	locked, err := loadWindowsEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	defer locked.Close()
	var lease *windowsservice.SyncPeerLease
	// nativeHandleConn 让 Close 与读取原生 pipe handle 的整个认证过程互斥。
	err = useNative(conn, func(raw net.Conn) error {
		var e error
		lease, e = windowsservice.AuthenticateSyncPipe(raw, locked.Config, incoming)
		return e
	})
	if err != nil {
		return nil, err
	}
	return lease, nil
}
func accountTransportAvailable(endpoint Endpoint) bool { return endpoint.WindowsConfigFile != "" }
