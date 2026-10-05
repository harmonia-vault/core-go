//go:build !windows

package windowsservice

import "net"

type SyncPeerLease struct{}

func (*SyncPeerLease) Close() error                                       { return nil }
func AuthenticateSyncPipe(net.Conn, Config, bool) (*SyncPeerLease, error) { return nil, ErrUnavailable }
