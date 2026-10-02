//go:build darwin || linux

package localipc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const socketName = "harmonia.sock"
const ownerMarker = "harmonia/localipc/v1"

func unixIdentity(endpoint Endpoint) (uint32, error) {
	n, err := strconv.ParseUint(endpoint.UserID, 10, 32)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != endpoint.UserID || endpoint.ServiceSID != "" || uint32(os.Geteuid()) != uint32(n) {
		return 0, ErrIdentity
	}
	if !filepath.IsAbs(endpoint.Directory) || filepath.Clean(endpoint.Directory) != endpoint.Directory || len(filepath.Join(endpoint.Directory, socketName)) > 100 {
		return 0, ErrProtocol
	}
	return uint32(n), nil
}
func unixDirectory(endpoint Endpoint, create bool) (uint32, error) {
	uid, err := unixIdentity(endpoint)
	if err != nil {
		return 0, err
	}
	// 父目录须由调用方预先准备，并显式解析系统路径链接。只建立最后一级目录，
	// 不沿用户给出的链接或未知祖先创建服务路径。
	parent, err := filepath.EvalSymlinks(filepath.Dir(endpoint.Directory))
	if err != nil || parent != filepath.Dir(endpoint.Directory) {
		return 0, ErrIdentity
	}
	if create {
		if err = os.Mkdir(endpoint.Directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return 0, ErrUnavailable
		}
	}
	canonical, err := filepath.EvalSymlinks(endpoint.Directory)
	if err != nil || canonical != endpoint.Directory {
		return 0, ErrIdentity
	}
	info, err := os.Lstat(endpoint.Directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return 0, ErrIdentity
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return 0, ErrIdentity
	}
	return uid, nil
}
func openOwned(path string, uid uint32) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrIdentity
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, ErrIdentity
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		_ = f.Close()
		return nil, ErrIdentity
	}
	return f, nil
}
func listenNative(endpoint Endpoint) (nativeListener, error) {
	uid, err := unixDirectory(endpoint, true)
	if err != nil {
		return nativeListener{}, err
	}
	lock, err := openOwned(filepath.Join(endpoint.Directory, "ipc.lock"), uid)
	if err != nil {
		return nativeListener{}, err
	}
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = lock.Close()
		return nativeListener{}, ErrUnavailable
	}
	release := func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN); _ = lock.Close() }
	markerPath := filepath.Join(endpoint.Directory, "ipc-owner.json")
	markerExists := true
	markerInfo, markerErr := os.Lstat(markerPath)
	if markerErr == nil {
		stat, ok := markerInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uid || !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm() != 0600 {
			release()
			return nativeListener{}, ErrIdentity
		}
	}
	marker, err := os.Open(markerPath)
	if errors.Is(err, os.ErrNotExist) {
		markerExists = false
	} else if err != nil {
		release()
		return nativeListener{}, ErrIdentity
	}
	if markerExists {
		var record struct {
			Schema string `json:"schema"`
			UID    uint32 `json:"uid"`
		}
		info, statErr := marker.Stat()
		decoder := json.NewDecoder(io.LimitReader(marker, 4096))
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&record)
		var extra any
		extraErr := decoder.Decode(&extra)
		_ = marker.Close()
		if statErr != nil || info.Size() > 4096 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || record.Schema != ownerMarker || record.UID != uid || decodeErr != nil || extraErr != io.EOF {
			release()
			return nativeListener{}, ErrIdentity
		}
	}
	socketPath := filepath.Join(endpoint.Directory, socketName)
	if info, err := os.Lstat(socketPath); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !markerExists || info.Mode()&os.ModeSocket == 0 || !ok || stat.Uid != uid {
			release()
			return nativeListener{}, ErrIdentity
		}
		if os.Remove(socketPath) != nil {
			release()
			return nativeListener{}, ErrUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		release()
		return nativeListener{}, ErrUnavailable
	}
	if !markerExists {
		f, err := openOwned(markerPath, uid)
		if err != nil {
			release()
			return nativeListener{}, err
		}
		data, _ := json.Marshal(struct {
			Schema string `json:"schema"`
			UID    uint32 `json:"uid"`
		}{ownerMarker, uid})
		_, err = f.Write(append(data, '\n'))
		if err == nil {
			err = f.Sync()
		}
		_ = f.Close()
		if err != nil {
			release()
			return nativeListener{}, ErrUnavailable
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		release()
		return nativeListener{}, ErrUnavailable
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(socketPath, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		release()
		return nativeListener{}, ErrIdentity
	}
	socketInfo, err := os.Lstat(socketPath)
	if err != nil {
		_ = listener.Close()
		release()
		return nativeListener{}, ErrUnavailable
	}
	cleanup := func() error {
		var removeErr error
		if current, err := os.Lstat(socketPath); err == nil && os.SameFile(socketInfo, current) {
			removeErr = os.Remove(socketPath)
		}
		release()
		return removeErr
	}
	return nativeListener{Listener: listener, cleanup: cleanup}, nil
}
func dialNative(ctx context.Context, endpoint Endpoint) (net.Conn, error) {
	uid, err := unixDirectory(endpoint, false)
	if err != nil {
		return nil, err
	}
	socketPath := filepath.Join(endpoint.Directory, socketName)
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return nil, ErrIdentity
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return nil, ErrIdentity
	}
	return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
}
func authorizeNative(conn net.Conn, endpoint Endpoint, server bool) error {
	uid, err := unixIdentity(endpoint)
	if err != nil {
		return err
	}
	return useNative(conn, func(connection net.Conn) error {
		socket, ok := connection.(*net.UnixConn)
		if !ok {
			return ErrIdentity
		}
		raw, err := socket.SyscallConn()
		if err != nil {
			return ErrIdentity
		}
		var peer uint32
		var peerErr error
		if raw.Control(func(fd uintptr) { peer, peerErr = peerUID(int(fd)) }) != nil || peerErr != nil || peer != uid {
			return ErrIdentity
		}
		return nil
	})
}

// CurrentUserID 返回公开本地身份，不读取环境变量或凭据。
func CurrentUserID() (string, error) {
	if os.Geteuid() == 0 {
		return "", ErrIdentity
	}
	return strconv.Itoa(os.Geteuid()), nil
}
