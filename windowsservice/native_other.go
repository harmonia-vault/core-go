//go:build !windows

package windowsservice

import (
	"context"
	"net"
)

func nativeClientIdentity(Config) error                           { return ErrUnavailable }
func nativeDialProfile(context.Context, Config) (net.Conn, error) { return nil, ErrUnavailable }
func nativeServerIdentity(net.Conn, Config) error                 { return ErrUnavailable }
