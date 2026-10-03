//go:build linux

package linuxinstall

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// 真实 Linux FD/lock 持久性测试仅在新 VM 的 root 临时目录运行。
// 不访问生产固定目录，也不修改 systemd。
func temporaryAdminStore(t *testing.T) *AdminStore {
	t.Helper()
	if os.Geteuid() != 0 || os.Getuid() != 0 || os.Getgid() != 0 {
		t.Skip("requires isolated Linux root test directory")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "harmonia-installer")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	pfd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dfd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if unix.Fstat(dfd, &st) != nil {
		t.Fatal("stat")
	}
	s := &AdminStore{dir: dfd, parent: pfd, dev: uint64(st.Dev), ino: st.Ino}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}
func TestLinuxRootJournalRealCASLockAndPersistence(t *testing.T) {
	s := temporaryAdminStore(t)
	l, err := s.Acquire("10001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Acquire("10001"); err != ErrBusy {
		t.Fatal("same UID lock not exclusive")
	}
	if s.Close() != ErrBusy {
		t.Fatal("store closed while lease live")
	}
	r := syntheticReceipt(t)
	r.Phase = "install-planned"
	if err = l.CreateReceipt(r); err != nil {
		t.Fatal(err)
	}
	if l.CreateReceipt(r) != ErrConflict {
		t.Fatal("receipt overwritten")
	}
	j := syntheticJournal(t, "uninstall-requested")
	if err = l.CreateJournal(j); err != nil {
		t.Fatal(err)
	}
	if err = l.CreateUninstallGuard(); err != nil {
		t.Fatal(err)
	}
	if err = l.CreateUninstallGuard(); err != nil {
		t.Fatal("guard retry failed", err)
	}
	next := cloneJournal(j)
	next.Phase = "service-drained"
	next.Revision++
	if err = l.CommitJournal(99, next); err != ErrConflict {
		t.Fatal("wrong revision overwrote journal")
	}
	if err = l.CommitJournal(j.Revision, next); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = s.Acquire("10001")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got, err := l.LoadJournal()
	if err != nil || got.Revision != 2 || got.Phase != "service-drained" {
		t.Fatal("restart did not read exact persisted commit")
	}
}
func TestLinuxRootStoreRejectsSymlinkHardlinkAndUnknownReplacement(t *testing.T) {
	s := temporaryAdminStore(t)
	l, err := s.Acquire("10001")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r := syntheticReceipt(t)
	r.Phase = "install-planned"
	if err = l.CreateReceipt(r); err != nil {
		t.Fatal(err)
	}
	if err = unix.Linkat(s.dir, "10001.installation.json", s.dir, "another-link", 0); err != nil {
		t.Fatal(err)
	}
	if _, err = l.LoadReceipt(); err != ErrPermission {
		t.Fatal("hardlink record accepted")
	}
	if err = unix.Unlinkat(s.dir, "another-link", 0); err != nil {
		t.Fatal(err)
	}
	if err = unix.Unlinkat(s.dir, "10001.installation.json", 0); err != nil {
		t.Fatal(err)
	}
	if err = unix.Symlinkat("/etc/passwd", s.dir, "10001.installation.json"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.LoadReceipt(); err != ErrPermission {
		t.Fatal("symlink followed")
	}
	if err = unix.Unlinkat(s.dir, "10001.installation.json", 0); err != nil {
		t.Fatal(err)
	}
	if _, err = l.LoadReceipt(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing record silently bootstrapped")
	}
}

func TestLinuxAuthorityReadResyncFailureCannotAdvanceJournal(t *testing.T) {
	s := temporaryAdminStore(t)
	l, e := s.Acquire("10001")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	r := syntheticReceipt(t)
	r.Phase = "install-planned"
	if e = l.CreateReceipt(r); e != nil {
		t.Fatal(e)
	}
	j := syntheticJournal(t, "uninstall-requested")
	if e = l.CreateJournal(j); e != nil {
		t.Fatal(e)
	}
	calls := 0
	s.resyncAuthority = func(fd, parent int) error { calls++; return unix.EIO }
	if _, e = l.LoadJournal(); e != ErrPersistence {
		t.Fatal("unsynced revision became authority", e)
	}
	n := cloneJournal(j)
	n.Phase = "service-drained"
	n.Revision++
	if e = l.CommitJournal(j.Revision, n); e != ErrPersistence {
		t.Fatal("read sync failure advanced state", e)
	}
	if calls != 2 {
		t.Fatal("resync path not exercised")
	}
	s.resyncAuthority = nil
	got, e := l.LoadJournal()
	if e != nil || got.Revision != j.Revision || got.Phase != j.Phase {
		t.Fatal("failed resync altered original transaction")
	}
}
