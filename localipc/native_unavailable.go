//go:build !darwin && !linux && !windows

package localipc

import (
	"context"
	"net"
)

// Windows named pipe 适配加入成熟依赖及 SID 验证后替换此关闭实现。
func listenNative(Endpoint) (nativeListener, error)          { return nativeListener{}, ErrUnavailable }
func dialNative(context.Context, Endpoint) (net.Conn, error) { return nil, ErrUnavailable }
func authorizeNative(net.Conn, Endpoint, bool) error         { return ErrIdentity }
func CurrentUserID() (string, error)                         { return "", ErrUnavailable }
