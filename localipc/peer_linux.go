//go:build linux

package localipc

import "golang.org/x/sys/unix"

func peerUID(fd int) (uint32, error) {
	credentials, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return credentials.Uid, nil
}
