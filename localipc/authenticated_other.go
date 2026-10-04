//go:build !windows

package localipc

import (
	"io"
	"net"
)

func authenticateFrameNative(net.Conn, Endpoint, bool) (io.Closer, error) { return nil, ErrIdentity }
func accountTransportAvailable(Endpoint) bool                             { return false }
