//go:build darwin

package macosservice

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func (f *darwinFS) durableAbsence(p string) (err error) {
	fd, name, e := f.parent(p)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	return syncAbsentAt(fd, name)
}

// 同一个经核验的父FD上确认确实缺失、再同步；存在或任意其他错误都拒绝。
func syncAbsentAt(fd int, name string) error {
	_, err := inspectAt(fd, name)
	if !errors.Is(err, os.ErrNotExist) {
		return ErrUnknown
	}
	return unix.Fsync(fd)
}
