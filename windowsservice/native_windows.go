//go:build windows

package windowsservice

import (
	"context"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"net"
)

const pipeClientAccess = windows.READ_CONTROL | windows.SYNCHRONIZE | windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES

func nativeDialProfile(ctx context.Context, c Config) (net.Conn, error) {
	if nativeClientIdentity(c) != nil {
		return nil, ErrIdentity
	}
	return winio.DialPipeAccessImpLevel(ctx, c.ProfilePipe(), pipeClientAccess, winio.PipeImpLevelIdentification)
}
func nativeListener(name, reader string) (net.Listener, error) {
	return winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "O:SYG:SYD:P(A;;GA;;;SY)(A;;0x00120083;;;" + reader + ")", InputBufferSize: 65536, OutputBufferSize: 65536})
}
