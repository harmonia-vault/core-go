//go:build windows

package localipc

import (
	"github.com/harmonia-vault/core-go/windowsaccount"
	"io"
	"net"
	"path/filepath"
	"strings"
)

func loadAccountEndpoint(e Endpoint) (*windowsaccount.LockedConfiguration, error) {
	l, err := windowsaccount.LoadConfiguration(e.AccountServiceConfig)
	if err != nil {
		return nil, ErrIdentity
	}
	sid, err := l.ServiceSID()
	p := l.Configuration.Plan
	if err != nil || e.UserID != p.TargetSID || e.ServiceSID != sid || !strings.EqualFold(e.Directory, filepath.Join(p.StateDirectory(), "ipc")) {
		_ = l.Close()
		return nil, ErrIdentity
	}
	return l, nil
}
func authenticateFrameNative(conn net.Conn, e Endpoint, incoming bool) (io.Closer, error) {
	locked, err := loadAccountEndpoint(e)
	if err != nil {
		return nil, err
	}
	defer locked.Close()
	var lease *windowsaccount.PeerLease
	err = useNative(conn, func(raw net.Conn) error {
		var x error
		lease, x = windowsaccount.AuthenticatePeer(raw, e.AccountServiceConfig, incoming)
		return x
	})
	return lease, err
}
func accountTransportAvailable(e Endpoint) bool { return e.AccountServiceConfig != "" }
