//go:build darwin

package macosservice

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/harmonia-vault/core-go/internal/launchctlprint"

	"golang.org/x/sys/unix"
)

// New 只创建控制器；不创建文件、不启动服务。
func New(t Target) (*Manager, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrUnsafe
	}
	if e := validateTarget(t); e != nil {
		return nil, e
	}
	byName, e := user.Lookup(t.UserName)
	if e != nil {
		return nil, ErrUnsafe
	}
	uid := strconv.FormatUint(uint64(t.UID), 10)
	byUID, e := user.LookupId(uid)
	if e != nil || !matchingIdentity(t, identity{byName.Username, byName.Uid, byName.Gid}, identity{byUID.Username, byUID.Uid, byUID.Gid}) {
		return nil, ErrUnsafe
	}
	return &Manager{target: t, fs: &darwinFS{target: t}, runner: darwinRunner{}}, nil
}

type darwinFS struct{ target Target }

func fromStat(s unix.Stat_t) node {
	k := other
	switch s.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		k = directory
	case unix.S_IFREG:
		k = regular
	case unix.S_IFSOCK:
		k = socket
	}
	return node{Kind: k, UID: s.Uid, GID: s.Gid, Mode: uint32(s.Mode) & 07777, Device: uint64(s.Dev), Inode: s.Ino, Links: uint64(s.Nlink)}
}

// 官方 SDK sys/attr.h/sys/kauth.h 的只读 fgetattrlist ABI，与 localkeys 相同。
// 任意非空扩展 ACL 保守拒绝；不解释或修改 ACL。
func extendedACL(fd int) (bool, error) {
	type attributeList struct {
		Count, Reserved                       uint16
		Common, Volume, Directory, File, Fork uint32
	}
	a := attributeList{Count: 5, Common: 0x00400000}
	b := make([]byte, 8192)
	_, _, errno := syscall.Syscall6(228, uintptr(fd), uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	if errno != 0 {
		return false, ErrUnsafe
	}
	l := int(binary.LittleEndian.Uint32(b[:4]))
	if l < 12 || l > len(b) {
		return false, ErrUnsafe
	}
	o := int(int32(binary.LittleEndian.Uint32(b[4:8]))) + 4
	s := int(binary.LittleEndian.Uint32(b[8:12]))
	if s == 0 {
		return false, nil
	}
	if o < 12 || s < 44 || o+s > l {
		return false, ErrUnsafe
	}
	c := binary.LittleEndian.Uint32(b[o+36 : o+40])
	return c != 0 && c != 0xffffffff, nil
}
func statFD(fd int) (node, error) {
	var s unix.Stat_t
	if e := unix.Fstat(fd, &s); e != nil {
		return node{}, e
	}
	n := fromStat(s)
	a, e := extendedACL(fd)
	n.ACL = a
	return n, e
}
func (f *darwinFS) dirAllowed(path string, n node) bool {
	if n.Kind != directory || n.ACL {
		return false
	}
	l := paths(f.target)
	if path == l.State || path == l.State+"/ipc" {
		return (n.UID == f.target.UID && n.GID == f.target.GID || n.UID == 0 && n.GID == 0) && n.Mode == 0700
	}
	ancestor := func(dst string) bool { return path == "/" || path == dst || strings.HasPrefix(dst, path+"/") }
	return n.UID == 0 && n.Mode&022 == 0 && (!(ancestor(l.Program) || ancestor(l.State)) || readableByTarget(n, f.target))
}
func (f *darwinFS) openDir(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, ErrUnsafe
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	n, e := statFD(fd)
	if e != nil || !f.dirAllowed("/", n) {
		unix.Close(fd)
		return -1, ErrUnsafe
	}
	if path == "/" {
		return fd, nil
	}
	cur := ""
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		cur += "/" + part
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
		n, e = statFD(fd)
		if e != nil || !f.dirAllowed(cur, n) {
			unix.Close(fd)
			return -1, ErrUnsafe
		}
	}
	return fd, nil
}
func (f *darwinFS) parent(p string) (int, string, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return -1, "", ErrUnsafe
	}
	fd, e := f.openDir(filepath.Dir(p))
	return fd, filepath.Base(p), e
}
func inspectAt(fd int, name string) (node, error) {
	var s unix.Stat_t
	if e := unix.Fstatat(fd, name, &s, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return node{}, e
	}
	n := fromStat(s)
	if n.Kind == other {
		return n, nil
	}
	child, e := unix.Openat(fd, name, unix.O_EVTONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return node{}, e
	}
	defer unix.Close(child)
	opened, e := statFD(child)
	if e != nil || !opened.same(n) {
		return node{}, ErrUnknown
	}
	return opened, nil
}
func (f *darwinFS) inspect(p string) (node, error) {
	if p == "/" {
		fd, e := f.openDir(p)
		if e != nil {
			return node{}, e
		}
		defer unix.Close(fd)
		return statFD(fd)
	}
	fd, name, e := f.parent(p)
	if e != nil {
		return node{}, e
	}
	defer unix.Close(fd)
	return inspectAt(fd, name)
}
func (f *darwinFS) read(p string, expected node, max int) ([]byte, error) {
	fd, name, e := f.parent(p)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	child, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(child), name)
	defer file.Close()
	n, e := statFD(child)
	if e != nil || !n.same(expected) || n.UID != expected.UID || n.GID != expected.GID || n.Mode != expected.Mode || n.Links != 1 || n.ACL {
		return nil, ErrUnknown
	}
	b, e := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if e != nil {
		return nil, e
	}
	if len(b) > max {
		return nil, ErrUnsafe
	}
	after, e := statFD(child)
	if e != nil || !after.same(n) || after.UID != n.UID || after.GID != n.GID || after.Mode != n.Mode || after.Links != n.Links || after.ACL {
		return nil, ErrUnknown
	}
	return b, nil
}
func (f *darwinFS) mkdir(p string, uid, gid, mode uint32) (n node, err error) {
	fd, name, e := f.parent(p)
	if e != nil {
		return n, e
	}
	defer unix.Close(fd)
	if e = unix.Mkdirat(fd, name, 0700); e != nil {
		return n, e
	}
	child, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return n, e
	}
	defer unix.Close(child)
	n, e = statFD(child)
	if e != nil {
		return n, e
	}
	defer func() {
		if err != nil {
			_ = removeAt(fd, name, n)
		}
	}()
	if n.ACL || n.UID != 0 {
		return n, ErrUnsafe
	}
	if e = unix.Fchown(child, int(uid), int(gid)); e != nil {
		return n, e
	}
	if e = unix.Fchmod(child, mode); e != nil {
		return n, e
	}
	n, e = statFD(child)
	if e != nil {
		return n, e
	}
	if n.UID != uid || n.GID != gid || n.Mode != mode || n.ACL {
		return n, ErrUnsafe
	}
	return n, unix.Fsync(fd)
}
func (f *darwinFS) write(p string, b []byte, mode uint32) (n node, err error) {
	fd, name, e := f.parent(p)
	if e != nil {
		return n, e
	}
	defer unix.Close(fd)
	child, e := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return n, e
	}
	file := os.NewFile(uintptr(child), name)
	defer file.Close()
	n, e = statFD(child)
	if e != nil {
		return n, e
	}
	defer func() {
		if err != nil {
			_ = removeAt(fd, name, n)
		}
	}()
	if n.ACL || n.UID != 0 || n.Kind != regular || n.Links != 1 {
		return n, ErrUnsafe
	}
	if _, e = file.Write(b); e != nil {
		return n, e
	}
	if e = unix.Fchown(child, 0, 0); e != nil {
		return n, e
	}
	if e = unix.Fchmod(child, mode); e != nil {
		return n, e
	}
	if e = file.Sync(); e != nil {
		return n, e
	}
	n, e = statFD(child)
	if e != nil {
		return n, e
	}
	return n, unix.Fsync(fd)
}
func (f *darwinFS) children(p string) ([]entry, error) {
	fd, e := f.openDir(p)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(fd), p)
	defer file.Close()
	xs, e := file.ReadDir(128)
	if errors.Is(e, io.EOF) {
		e = nil
	}
	if e != nil {
		return nil, e
	}
	if len(xs) == 128 {
		return nil, ErrUnknown
	}
	out := make([]entry, 0, len(xs))
	for _, x := range xs {
		n, e := inspectAt(fd, x.Name())
		if e != nil {
			return nil, e
		}
		out = append(out, entry{x.Name(), n})
	}
	return out, nil
}
func removeAt(fd int, name string, expected node) error {
	n, e := inspectAt(fd, name)
	if e != nil {
		return e
	}
	if !equalNode(n, expected) {
		return ErrUnknown
	}
	flags := 0
	if n.Kind == directory {
		flags = unix.AT_REMOVEDIR
	}
	if e = unix.Unlinkat(fd, name, flags); e != nil {
		return e
	}
	return unix.Fsync(fd)
}
func (f *darwinFS) remove(p string, expected node) (err error) {
	fd, name, e := f.parent(p)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	return removeAt(fd, name, expected)
}
func (f *darwinFS) owner(p string, expected node, uid, gid uint32) (node, error) {
	fd, name, e := f.parent(p)
	if e != nil {
		return node{}, e
	}
	defer unix.Close(fd)
	child, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return node{}, e
	}
	defer unix.Close(child)
	n, e := statFD(child)
	if e != nil || !n.same(expected) || n.ACL || n.Mode != 0700 {
		return node{}, ErrUnknown
	}
	if e = unix.Fchown(child, int(uid), int(gid)); e != nil {
		return node{}, e
	}
	if e = unix.Fsync(child); e != nil {
		return node{}, e
	}
	if e = unix.Fsync(fd); e != nil {
		return node{}, e
	}
	return statFD(child)
}

type heldLock struct{ file *os.File }

func (h heldLock) Close() error {
	return errors.Join(unix.Flock(int(h.file.Fd()), unix.LOCK_UN), h.file.Close())
}
func (f *darwinFS) claimLock(p string, expected node) (io.Closer, error) {
	fd, name, e := f.parent(p)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	uid := f.target.UID
	if p == paths(f.target).Control {
		uid = 0
		if expected.GID != 0 {
			return nil, ErrUnknown
		}
	}
	return claimLockAt(fd, name, expected, uid)
}
func claimLockAt(fd int, name string, expected node, targetUID uint32) (io.Closer, error) {
	child, e := unix.Openat(fd, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(child), name)
	n, e := statFD(child)
	if e != nil || !equalNode(n, expected) || n.Kind != regular || n.UID != targetUID || n.Mode != 0600 || n.Links != 1 || n.ACL {
		file.Close()
		return nil, ErrUnknown
	}
	if e = unix.Flock(child, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		file.Close()
		return nil, ErrUnknown
	}
	current, e := inspectAt(fd, name)
	if e != nil || !equalNode(current, n) {
		file.Close()
		return nil, ErrUnknown
	}
	return heldLock{file}, nil
}

type darwinRunner struct{}

func safeCommand(ctx context.Context, p string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, p, args...)
	c.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	return c
}
func launchState(b []byte, exit int, l layout, t Target) serviceState {
	text := strings.TrimSpace(string(b))
	if exit != 0 {
		if exit == 113 && strings.Contains(text, `Could not find service "`+l.Label+`"`) {
			return absent
		}
		return unknown
	}
	job, err := launchctlprint.Decode(b, l.Label)
	if err != nil {
		return unknown
	}
	// 只比较收据身份与顶层字段；嵌套运行统计不改变服务身份。
	values, args := job.Fields, job.Arguments
	if values["path"] != l.Plist || values["program"] != l.Binary || values["username"] != t.UserName || values["type"] != "LaunchDaemon" {
		return unknown
	}
	want := []string{l.Binary, "daemon", "--local-directory", l.State, "--local-user", strconv.FormatUint(uint64(t.UID), 10), "--interval", "2s"}
	if l.CAEnabled {
		want = append(want, "--ca-file", l.CA)
	}
	if len(args) != len(want) {
		return unknown
	}
	for i := range want {
		if args[i] != want[i] {
			return unknown
		}
	}
	return matching
}
func (darwinRunner) state(ctx context.Context, l layout, t Target) (serviceState, error) {
	b, e := safeCommand(ctx, "/bin/launchctl", "print", "system/"+l.Label).CombinedOutput()
	if len(b) > 2<<20 {
		return unknown, ErrUnknown
	}
	exit := 0
	if e != nil {
		var x *exec.ExitError
		if !errors.As(e, &x) {
			return unknown, ErrUnknown
		}
		exit = x.ExitCode()
	}
	s := launchState(b, exit, l, t)
	if s == unknown {
		return s, ErrUnknown
	}
	return s, nil
}
func (darwinRunner) bootstrap(ctx context.Context, l layout) error {
	if safeCommand(ctx, "/bin/launchctl", "bootstrap", "system", l.Plist).Run() != nil {
		return ErrUnknown
	}
	return nil
}
func (darwinRunner) bootout(ctx context.Context, l layout) error {
	if safeCommand(ctx, "/bin/launchctl", "bootout", "system/"+l.Label).Run() != nil {
		return ErrUnknown
	}
	return nil
}
func (darwinRunner) logout(ctx context.Context, l layout, t Target) error {
	args := []string{"logout", "--local-directory", l.State, "--local-user", strconv.FormatUint(uint64(t.UID), 10)}
	// CA 只影响本 CLI。由已验证的 root 收据确定是否启用。
	if l.CAEnabled {
		args = append(args, "--ca-file", l.CA)
	}
	c := safeCommand(ctx, l.Binary, args...)
	c.Dir = l.State
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: t.UID, Gid: t.GID, Groups: []uint32{}}}
	if c.Run() != nil {
		return ErrUnknown
	}
	return nil
}

func jobPID(b []byte, l layout, t Target) (int, error) {
	if launchState(b, 0, l, t) != matching {
		return 0, ErrUnknown
	}
	job, err := launchctlprint.Decode(b, l.Label)
	if err != nil {
		return 0, ErrUnknown
	}
	text, present := job.Fields["pid"]
	pid, err := strconv.Atoi(text)
	if !present || err != nil || pid < 2 || strconv.Itoa(pid) != text {
		return 0, ErrUnknown
	}
	return pid, nil
}
func (darwinRunner) controlledPID(ctx context.Context, l layout, t Target) (int, error) {
	b, e := safeCommand(ctx, "/bin/launchctl", "print", "system/"+l.Label).CombinedOutput()
	if e != nil || len(b) > 2<<20 {
		return 0, ErrUnknown
	}
	return jobPID(b, l, t)
}
func psExists(b []byte, exit, pid int) (bool, error) {
	text := strings.TrimSpace(string(b))
	if exit == 1 && text == "" {
		return false, nil
	}
	if exit == 0 && text == strconv.Itoa(pid) {
		return true, nil
	}
	return false, ErrUnknown
}
func (darwinRunner) waitExit(ctx context.Context, pid int) error {
	if pid < 2 || pid == os.Getpid() {
		return ErrUnknown
	}
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		// 仅查询先前受控的正 PID 数字；不读 argv/environment，不发送任何信号。
		b, e := safeCommand(deadline, "/bin/ps", "-p", strconv.Itoa(pid), "-o", "pid=").CombinedOutput()
		if len(b) > 128 {
			return ErrUnknown
		}
		exit := 0
		if e != nil {
			var x *exec.ExitError
			if !errors.As(e, &x) {
				return ErrUnknown
			}
			exit = x.ExitCode()
		}
		alive, e := psExists(b, exit, pid)
		if e != nil {
			return e
		}
		if !alive {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-deadline.Done():
			timer.Stop()
			return ErrUnknown
		case <-timer.C:
		}
	}
}
