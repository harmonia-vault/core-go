//go:build darwin

package macosservice

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// 仅普通用户自己的临时目录，不调用root安装入口或系统服务。
func TestDarwinV6AbsenceIsCheckedAndSyncedOnSameParentFD(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := os.WriteFile(filepath.Join(dir, "current"), []byte("synthetic-only"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := syncAbsentAt(fd, "current"); err == nil {
		t.Fatal("存在的项被当作持久缺失")
	}
	if err := unix.Unlinkat(fd, "current", 0); err != nil {
		t.Fatal(err)
	}
	if err := syncAbsentAt(fd, "current"); err != nil {
		t.Fatal("同一父FD的实际缺失同步失败", err)
	}
}
