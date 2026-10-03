//go:build linux

package linuxinstall

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// AdminStore 只供 root 安装器固定目录使用，不接 caller 自选目录/身份。
type AdminStore struct {
	mu     sync.Mutex
	dir    int
	parent int
	dev    uint64
	ino    uint64
	closed bool
	leases int
	// 非导出故障注入仅供同包隔离 Linux temp 测试；正式构造始终 nil。
	resyncAuthority func(int, int) error
}
type AdminLease struct {
	mu     sync.Mutex
	store  *AdminStore
	lock   *os.File
	uid    string
	closed bool
}

func checkACL(fd int, directory bool) error {
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
func rootIdentity() error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return ErrPermission
	}
	return nil
}
func rootFile(fd int, mode uint32) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != mode || st.Nlink != 1 {
		return ErrPermission
	}
	return checkACL(fd, false)
}
func rootDir(fd int, mode uint32) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != mode {
		return ErrPermission
	}
	return checkACL(fd, true)
}

// OpenAdminStore 不 bootstrap 不存在的目录。新安装需另一个经审准备阶段创建它。
func OpenAdminStore() (*AdminStore, error) {
	if rootIdentity() != nil {
		return nil, ErrPermission
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrPermission
	}
	for _, part := range []string{"var", "lib"} {
		if rootDir(fd, 0755) != nil {
			unix.Close(fd)
			return nil, ErrPermission
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, ErrPermission
		}
		fd = next
	}
	if rootDir(fd, 0755) != nil {
		unix.Close(fd)
		return nil, ErrPermission
	}
	parent := fd
	dir, err := unix.Openat(parent, "harmonia-installer", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(parent)
		return nil, ErrPermission
	}
	if rootDir(dir, 0700) != nil {
		unix.Close(dir)
		unix.Close(parent)
		return nil, ErrPermission
	}
	var st unix.Stat_t
	if unix.Fstat(dir, &st) != nil {
		unix.Close(dir)
		unix.Close(parent)
		return nil, ErrPermission
	}
	return &AdminStore{dir: dir, parent: parent, dev: uint64(st.Dev), ino: st.Ino}, nil
}
func (s *AdminStore) guard() error {
	if s.closed || rootIdentity() != nil || rootDir(s.dir, 0700) != nil || rootDir(s.parent, 0755) != nil {
		return ErrPermission
	}
	var st unix.Stat_t
	if unix.Fstatat(s.parent, "harmonia-installer", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || uint64(st.Dev) != s.dev || st.Ino != s.ino {
		return ErrPermission
	}
	return nil
}
func (s *AdminStore) Acquire(uid string) (*AdminLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.guard() != nil || !decimalID(uid, true) {
		return nil, ErrPermission
	}
	name := uid + ".lock"
	fd, err := unix.Openat(s.dir, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(s.dir, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	} else if err == nil {
		if unix.Fsync(s.dir) != nil {
			unix.Close(fd)
			return nil, ErrPersistence
		}
	}
	if err != nil {
		return nil, ErrPermission
	}
	f := os.NewFile(uintptr(fd), name)
	if rootFile(fd, 0600) != nil {
		f.Close()
		return nil, ErrPermission
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrBusy
		}
		return nil, ErrPermission
	}
	s.leases++
	return &AdminLease{store: s, lock: f, uid: uid}, nil
}
func (s *AdminStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.leases > 0 {
		return ErrBusy
	}
	s.closed = true
	return errors.Join(unix.Close(s.dir), unix.Close(s.parent))
}
func (l *AdminLease) guard() error {
	if l.closed || l.store.guard() != nil || rootFile(int(l.lock.Fd()), 0600) != nil {
		return ErrPermission
	}
	var held, current unix.Stat_t
	if unix.Fstat(int(l.lock.Fd()), &held) != nil || unix.Fstatat(l.store.dir, l.uid+".lock", &current, unix.AT_SYMLINK_NOFOLLOW) != nil || held.Dev != current.Dev || held.Ino != current.Ino {
		return ErrPermission
	}
	return nil
}
func (l *AdminLease) read(name string) ([]byte, error) {
	if l.guard() != nil {
		return nil, ErrPermission
	}
	fd, err := unix.Openat(l.store.dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		if unix.Fsync(l.store.dir) != nil {
			return nil, ErrPersistence
		}
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, ErrPermission
	}
	f := os.NewFile(uintptr(fd), name)
	if rootFile(fd, 0600) != nil {
		f.Close()
		return nil, ErrPermission
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxRecordBytes+1))
	// A prior rename may have completed while its parent fsync failed. Re-sync the
	// current inode and parent before treating the observed revision as authority.
	syncErr := error(nil)
	if e == nil && len(b) <= MaxRecordBytes {
		if l.store.resyncAuthority != nil {
			syncErr = l.store.resyncAuthority(fd, l.store.dir)
		} else {
			syncErr = errors.Join(f.Sync(), unix.Fsync(l.store.dir))
		}
	}
	closeErr := f.Close()
	if e != nil || syncErr != nil || closeErr != nil || len(b) > MaxRecordBytes {
		return nil, ErrPersistence
	}
	return b, nil
}
func (l *AdminLease) write(name string, data []byte, exclusive bool) error {
	if l.guard() != nil {
		return ErrPermission
	}
	if len(data) == 0 || len(data) > MaxRecordBytes {
		return ErrState
	}
	if old, err := l.read(name); err == nil {
		clear(old)
		if exclusive {
			return ErrConflict
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return ErrPersistence
	}
	tmp := ".linux-install-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(l.store.dir, tmp, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrPersistence
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer unix.Unlinkat(l.store.dir, tmp, 0)
	if rootFile(fd, 0600) != nil {
		f.Close()
		return ErrPermission
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return ErrPersistence
	}
	if f.Sync() != nil {
		f.Close()
		return ErrPersistence
	}
	if f.Close() != nil {
		return ErrPersistence
	}
	if l.guard() != nil {
		return ErrPermission
	}
	if exclusive {
		err = unix.Renameat2(l.store.dir, tmp, l.store.dir, name, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.EEXIST) {
			return ErrConflict
		}
		if err != nil {
			if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
				return ErrUnsupported
			}
			return ErrPersistence
		}
	} else if unix.Renameat(l.store.dir, tmp, l.store.dir, name) != nil {
		return ErrPersistence
	}
	if unix.Fsync(l.store.dir) != nil {
		return ErrPersistence
	}
	b, err := l.read(name)
	if err != nil || !bytes.Equal(b, data) {
		return ErrPersistence
	}
	return nil
}
func (l *AdminLease) LoadReceipt() (Receipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, err := l.read(l.uid + ".installation.json")
	if err != nil {
		return Receipt{}, err
	}
	r, err := DecodeReceipt(b)
	if err != nil || r.Plan.Input.UID != l.uid {
		return Receipt{}, ErrState
	}
	return r, nil
}
func (l *AdminLease) CreateReceipt(r Receipt) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.Validate() != nil || r.Phase != "install-planned" || r.Plan.Input.UID != l.uid {
		return ErrState
	}
	b, err := json.Marshal(r)
	if err != nil {
		return ErrState
	}
	return l.write(l.uid+".installation.json", b, true)
}
func (l *AdminLease) CommitReceipt(expected uint64, next Receipt) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if next.Plan.Input.UID != l.uid {
		return ErrState
	}
	b, err := l.read(l.uid + ".installation.json")
	if err != nil {
		return err
	}
	previous, err := DecodeReceipt(b)
	if err != nil || previous.Revision != expected || ValidateReceiptSuccessor(previous, next) != nil {
		return ErrConflict
	}
	b, err = json.Marshal(next)
	if err != nil {
		return ErrState
	}
	return l.write(l.uid+".installation.json", b, false)
}
func (l *AdminLease) LoadJournal() (Journal, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, err := l.read(l.uid + ".uninstall.json")
	if err != nil {
		return Journal{}, err
	}
	j, err := DecodeJournal(b)
	if err != nil || j.Plan.Input.UID != l.uid {
		return Journal{}, ErrState
	}
	return j, nil
}
func (l *AdminLease) CreateJournal(j Journal) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if j.Validate() != nil || j.Plan.Input.UID != l.uid || j.Phase != "uninstall-requested" || j.Revision != 1 {
		return ErrState
	}
	b, err := l.read(l.uid + ".installation.json")
	if err != nil {
		return err
	}
	r, err := DecodeReceipt(b)
	if err != nil || r.Plan != j.Plan || r.InstallationID != j.InstallationID {
		return ErrState
	}
	if j.Receipt != nil {
		a, _ := json.Marshal(r)
		b, _ := json.Marshal(j.Receipt)
		if !bytes.Equal(a, b) {
			return ErrState
		}
	}
	b, err = json.Marshal(j)
	if err != nil {
		return ErrState
	}
	return l.write(l.uid+".uninstall.json", b, true)
}
func (l *AdminLease) CommitJournal(expected uint64, next Journal) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if next.Plan.Input.UID != l.uid {
		return ErrState
	}
	b, err := l.read(l.uid + ".uninstall.json")
	if err != nil {
		return err
	}
	previous, err := DecodeJournal(b)
	if err != nil || previous.Revision != expected || ValidateSuccessor(previous, next) != nil {
		return ErrConflict
	}
	b, err = json.Marshal(next)
	if err != nil {
		return ErrState
	}
	return l.write(l.uid+".uninstall.json", b, false)
}

// CreateUninstallGuard 在实际 stop 前持久阻断本 unit。已存在只接受本安装 ID，
// 重试仍 fsync/readback，不用一次失败的内存结果假称 durable。
func (l *AdminLease) CreateUninstallGuard() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, err := l.read(l.uid + ".installation.json")
	if err != nil {
		return err
	}
	r, err := DecodeReceipt(b)
	if err != nil {
		return err
	}
	b, err = l.read(l.uid + ".uninstall.json")
	if err != nil {
		return err
	}
	j, err := DecodeJournal(b)
	if err != nil || j.Plan != r.Plan || j.InstallationID != r.InstallationID || j.Phase != "uninstall-requested" {
		return ErrState
	}
	want := []byte(r.InstallationID + "\n")
	name := l.uid + ".uninstalling"
	b, err = l.read(name)
	if errors.Is(err, os.ErrNotExist) {
		return l.write(name, want, true)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(b, want) {
		return ErrConflict
	}
	fd, err := unix.Openat(l.store.dir, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrPersistence
	}
	if rootFile(fd, 0600) != nil {
		unix.Close(fd)
		return ErrPermission
	}
	if unix.Fsync(fd) != nil {
		unix.Close(fd)
		return ErrPersistence
	}
	if unix.Close(fd) != nil || unix.Fsync(l.store.dir) != nil {
		return ErrPersistence
	}
	b, err = l.read(name)
	if err != nil || !bytes.Equal(b, want) {
		return ErrPersistence
	}
	return nil
}
func (l *AdminLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	err := errors.Join(unix.Flock(int(l.lock.Fd()), unix.LOCK_UN), l.lock.Close())
	l.store.mu.Lock()
	l.store.leases--
	l.store.mu.Unlock()
	return err
}

// 明确规划的 UID scope，在 Linux root-only primitive 内再次核验。
func parseUID(s string) (uint32, error) {
	if !decimalID(s, true) {
		return 0, ErrPlan
	}
	n, _ := strconv.ParseUint(s, 10, 32)
	return uint32(n), nil
}
