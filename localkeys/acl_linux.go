//go:build linux

package localkeys

import (
	"errors"
	"golang.org/x/sys/unix"
)

// 拒绝扩展 access/default ACL，避免 mode 位与实际访问权限不一致。
func checkExtendedACL(fd int, directory bool) error {
	names := []string{"system.posix_acl_access"}
	if directory {
		names = append(names, "system.posix_acl_default")
	}
	for _, name := range names {
		size, err := unix.Fgetxattr(fd, name, nil)
		if err == nil && size > 0 {
			return ErrPermission
		}
		if err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			return ErrPermission
		}
	}
	return nil
}
