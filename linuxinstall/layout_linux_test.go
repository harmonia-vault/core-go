//go:build linux

package linuxinstall

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// 首次 Fstatat 观察普通文件后，在真实 Openat 前换成无人写入的 FIFO。
// 只有测试私有调用点可控制这一时刻，不修改生产命名空间或系统服务。
func TestLinuxObservationRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	const name = "synthetic-observed-file"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	parent, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(parent); err != nil {
			t.Fatal(err)
		}
	}()
	opened := false
	started := time.Now()
	observed, err := observeAtWithOpen(parent, name, "state", func(fd int, path string, flags int, mode uint32) (int, error) {
		if fd != parent || path != name || flags&unix.O_NONBLOCK == 0 || flags&unix.O_NOFOLLOW == 0 {
			t.Fatal("observation must use bounded no-follow open")
		}
		if err := unix.Unlinkat(fd, path, 0); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifoat(fd, path, 0600); err != nil {
			t.Fatal(err)
		}
		opened = true
		return unix.Openat(fd, path, flags, mode)
	})
	if !opened || !errors.Is(err, ErrConflict) || observed != (Identity{}) {
		t.Fatalf("replacement accepted: opened=%t err=%v", opened, err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("replacement open exceeded bounded test window")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		t.Fatal("test must exercise an actual FIFO without a writer")
	}
}

// 经审 VM runner 固定 umask077；不改进程 umask或为通过降低权限检查。
func TestLinuxSharedCreationSetsExactModeAndPreservesExistingMismatch(t *testing.T) {
	if rootIdentity() != nil {
		t.Skip("isolated Linux root temp directory required")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	fs := layout{prefix: root}
	if err := fs.ensureShared("/new-shared-directory", 0755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(fs.path("/new-shared-directory"))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0755 {
		t.Fatal("new directory mode is not exact")
	}
	if err := fs.ensureShared("/new-shared-directory", 0755); err != nil {
		t.Fatal("exact existing directory cannot be checked", err)
	}
	const bad = "/unknown-existing-directory"
	if err := os.Mkdir(fs.path(bad), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fs.path(bad), 0700); err != nil {
		t.Fatal(err)
	}
	if err := fs.ensureShared(bad, 0755); !errors.Is(err, ErrPermission) {
		t.Fatal("existing mismatch was not rejected", err)
	}
	info, err = os.Lstat(fs.path(bad))
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("existing mismatch was changed")
	}
}
