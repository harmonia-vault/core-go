//go:build linux

package linuxinstall

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func checkCgroupDrained(ctx context.Context, group string) error {
	// group 唯一调用者由已核 Plan 构造，不接用户任意路径。
	if err := ctx.Err(); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if unix.Statfs("/sys/fs/cgroup", &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return ErrUnsupported
	}
	root := "/sys/fs/cgroup" + group
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrState
	}
	count := 0
	return filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if walkErr != nil {
			return ErrState
		}
		if d.Type()&os.ModeSymlink != 0 {
			return ErrState
		}
		if !d.IsDir() {
			return nil
		}
		count++
		if count > 64 {
			return ErrState
		}
		fd, err := unix.Open(filepath.Join(path, "cgroup.procs"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return ErrState
		}
		f := os.NewFile(uintptr(fd), "cgroup.procs")
		b, readErr := io.ReadAll(io.LimitReader(f, 4097))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return ErrState
		}
		return parseCgroupProcesses(b)
	})
}
