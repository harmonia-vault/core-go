//go:build linux

package linuxinstall

import (
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// layout 的 prefix 只供同包 root 临时目录测试；正式构造始终为空。
type layout struct{ prefix string }

func (l layout) path(s string) string {
	if l.prefix == "" {
		return s
	}
	return filepath.Join(l.prefix, strings.TrimPrefix(s, "/"))
}
func openDirectory(path string) (int, error) {
	if path != "/" && !absoluteClean(path) {
		return -1, ErrPermission
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrPermission
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			if errors.Is(e, unix.ENOENT) {
				return -1, os.ErrNotExist
			}
			return -1, ErrPermission
		}
		fd = next
	}
	return fd, nil
}
func observeAt(parent int, name, area string) (Identity, error) {
	return observeAtWithOpen(parent, name, area, unix.Openat)
}

// openAt 只用于同包受控替换测试；正式调用固定为 unix.Openat。
func observeAtWithOpen(parent int, name, area string, openAt func(int, string, int, uint32) (int, error)) (Identity, error) {
	var s unix.Stat_t
	if err := unix.Fstatat(parent, name, &s, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return Identity{}, os.ErrNotExist
		}
		return Identity{}, ErrPermission
	}
	kind := ""
	switch s.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		kind = "file"
	case unix.S_IFDIR:
		kind = "directory"
	case unix.S_IFLNK:
		kind = "symlink"
	case unix.S_IFSOCK:
		kind = "socket"
	default:
		return Identity{}, ErrPermission
	}
	i := Identity{Area: area, Name: name, Kind: kind, Device: uint64(s.Dev), Inode: s.Ino, UID: s.Uid, GID: s.Gid, Mode: s.Mode & 07777, Links: uint64(s.Nlink)}
	if kind == "symlink" {
		b := make([]byte, 4097)
		n, e := unix.Readlinkat(parent, name, b)
		if e != nil || n > 4096 {
			return Identity{}, ErrPermission
		}
		i.LinkTarget = string(b[:n])
	} else if kind != "socket" {
		// 观察后同 UID 仍可能把普通文件换成 FIFO。NONBLOCK 保证打开替换物
		// 不会无限等待；已打开 FD 必须与首次观察完全绑定后才能检查 ACL。
		flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if kind == "directory" {
			flags |= unix.O_DIRECTORY
		}
		fd, e := openAt(parent, name, flags, 0)
		if e != nil {
			return Identity{}, ErrPermission
		}
		var opened unix.Stat_t
		if unix.Fstat(fd, &opened) != nil {
			e = ErrPermission
		} else if opened.Dev != s.Dev || opened.Ino != s.Ino || opened.Mode != s.Mode || opened.Uid != s.Uid || opened.Gid != s.Gid || opened.Nlink != s.Nlink || opened.Rdev != s.Rdev {
			e = ErrConflict
		} else {
			e = checkACL(fd, kind == "directory")
		}
		closeErr := unix.Close(fd)
		if closeErr != nil {
			return Identity{}, ErrPermission
		}
		if e != nil {
			return Identity{}, e
		}
	}
	return i, nil
}
func targetPath(p Plan, area, name string) (string, error) {
	for _, c := range creationPlan(p) {
		if c.Area == area && c.Name == name {
			switch area {
			case "program-directory":
				return p.ProgramDirectory, nil
			case "program":
				return filepath.Join(p.ProgramDirectory, name), nil
			case "unit":
				return p.UnitPath, nil
			case "state-directory":
				return p.StateDirectory, nil
			}
		}
	}
	if area == "enable-link" && name == p.UnitName {
		return p.EnableLink, nil
	}
	if area == "state" && stateNames[name] {
		return filepath.Join(p.StateDirectory, name), nil
	}
	if area == "ipc" && ipcNames[name] != "" {
		return filepath.Join(p.StateDirectory, "ipc", name), nil
	}
	if area == "ipc-directory" && name == "ipc" {
		return filepath.Join(p.StateDirectory, "ipc"), nil
	}
	return "", ErrPlan
}
func (l layout) observe(p Plan, area, name string) (Identity, error) {
	path, err := targetPath(p, area, name)
	if err != nil {
		return Identity{}, err
	}
	fd, err := openDirectory(filepath.Dir(l.path(path)))
	if err != nil {
		return Identity{}, err
	}
	defer unix.Close(fd)
	return observeAt(fd, name, area)
}
func sameInode(a, b Identity) bool {
	return a.Area == b.Area && a.Name == b.Name && a.Device == b.Device && a.Inode == b.Inode && a.Kind == b.Kind
}
func (l layout) ensureShared(path string, mode uint32) (result error) {
	path = l.path(path)
	fd, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() {
		if unix.Close(fd) != nil {
			result = errors.Join(result, ErrPersistence)
		}
	}()
	if rootDir(fd, 0755) != nil {
		return ErrPermission
	}
	err = unix.Mkdirat(fd, filepath.Base(path), mode)
	created := err == nil
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return ErrPersistence
	}
	child, e := unix.Openat(fd, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrPermission
	}
	defer func() {
		if unix.Close(child) != nil {
			result = errors.Join(result, ErrPersistence)
		}
	}()
	if created {
		// 不改进程 umask。仅本次独占创建且仍在原名称的 root 目录
		// 可以显式设置权限；已有目录严格核原 mode，不能 chmod 修补。
		var opened, current unix.Stat_t
		if unix.Fstat(child, &opened) != nil || opened.Mode&unix.S_IFMT != unix.S_IFDIR || opened.Uid != 0 || opened.Gid != 0 || opened.Mode&07000 != 0 || opened.Mode&0777 & ^mode != 0 || checkACL(child, true) != nil {
			return ErrPermission
		}
		if unix.Fstatat(fd, filepath.Base(path), &current, unix.AT_SYMLINK_NOFOLLOW) != nil || current.Dev != opened.Dev || current.Ino != opened.Ino || current.Mode != opened.Mode || current.Uid != opened.Uid || current.Gid != opened.Gid || current.Nlink != opened.Nlink {
			return ErrConflict
		}
		if unix.Fchmod(child, mode) != nil {
			return ErrPersistence
		}
	}
	if rootDir(child, mode) != nil {
		return ErrPermission
	}
	if unix.Fsync(child) != nil || unix.Fsync(fd) != nil {
		return ErrPersistence
	}
	return nil
}
func rootSource(path string) (*os.File, error) {
	fd, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	n, e := unix.Openat(fd, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrPermission
	}
	f := os.NewFile(uintptr(n), "explicit-source")
	var st unix.Stat_t
	if unix.Fstat(n, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&07000 != 0 || st.Size < 1 || st.Size > 128<<20 || checkACL(n, false) != nil {
		f.Close()
		return nil, ErrPermission
	}
	size, e := unix.Fgetxattr(n, "security.capability", nil)
	if e == nil && size > 0 || e != nil && !errors.Is(e, unix.ENODATA) && !errors.Is(e, unix.ENOTSUP) {
		f.Close()
		return nil, ErrPermission
	}
	return f, nil
}
func checkedBinarySource(path, expected string) (*os.File, error) {
	f, e := rootSource(path)
	if e != nil {
		return nil, e
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil || hex.EncodeToString(h.Sum(nil)) != expected {
		f.Close()
		return nil, ErrConflict
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		f.Close()
		return nil, ErrPersistence
	}
	b, e := elf.NewFile(f)
	if e != nil {
		f.Close()
		return nil, ErrPlan
	}
	want := elf.EM_NONE
	switch runtime.GOARCH {
	case "arm64":
		want = elf.EM_AARCH64
	case "amd64":
		want = elf.EM_X86_64
	default:
		f.Close()
		return nil, ErrUnsupported
	}
	if b.Class != elf.ELFCLASS64 || b.Data != elf.ELFDATA2LSB || b.Machine != want || b.Type != elf.ET_EXEC && b.Type != elf.ET_DYN {
		f.Close()
		return nil, ErrPlan
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		f.Close()
		return nil, ErrPersistence
	}
	return f, nil
}
func (l layout) hashFile(path, expected string, mode uint32) error {
	f, e := rootSource(l.path(path))
	if e != nil {
		return e
	}
	defer f.Close()
	if rootFile(int(f.Fd()), mode) != nil {
		return ErrPermission
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return ErrPersistence
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		return ErrConflict
	}
	if f.Close() != nil {
		return ErrPersistence
	}
	return nil
}

func (l layout) create(p Plan, c Creation, r Receipt) error {
	path, e := targetPath(p, c.Area, c.Name)
	if e != nil {
		return e
	}
	fd, e := openDirectory(filepath.Dir(l.path(path)))
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if rootDir(fd, 0755) != nil && !(c.Area == "program" && rootDir(fd, 0700) == nil) {
		return ErrPermission
	}
	if c.Area == "program-directory" || c.Area == "state-directory" {
		if unix.Mkdirat(fd, c.Name, 0700) != nil {
			return ErrConflict
		}
		child, e := unix.Openat(fd, c.Name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return ErrPermission
		}
		syncErr := unix.Fsync(child)
		closeErr := unix.Close(child)
		if syncErr != nil || closeErr != nil {
			return ErrPersistence
		}
		if unix.Fsync(fd) != nil {
			return ErrPersistence
		}
		return nil
	}
	var source io.Reader
	var f *os.File
	var closeSource bool
	mode := uint32(0644)
	switch c.Area {
	case "unit":
		u, unitErr := r.unitTemplate()
		if unitErr != nil {
			return unitErr
		}
		source = strings.NewReader(string(u.Content))
	case "program":
		if c.Name == "harmonia" {
			f, e = checkedBinarySource(p.Input.BinarySource, p.Input.BinarySHA256)
			mode = 0755
		} else {
			f, e = checkedCASource(p.Input.CASource, p.Input.CASHA256)
		}
		if e != nil {
			return e
		}
		source = f
		closeSource = true
	default:
		return ErrPlan
	}
	if closeSource {
		defer func() {
			if closeSource {
				_ = f.Close()
			}
		}()
	}
	tmp := creationTemporaryName(r, c)
	n, e := unix.Openat(fd, tmp, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if errors.Is(e, unix.EEXIST) {
		n, e = unix.Openat(fd, tmp, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == nil && (rootFile(n, mode) != nil && rootFile(n, 0600) != nil || unix.Ftruncate(n, 0) != nil) {
			unix.Close(n)
			return ErrPermission
		}
	}
	if e != nil {
		return ErrPersistence
	}
	out := os.NewFile(uintptr(n), tmp)
	if unix.Fchmod(n, mode) != nil {
		out.Close()
		return ErrPersistence
	}
	h := sha256.New()
	count, e := io.Copy(io.MultiWriter(out, h), io.LimitReader(source, (128<<20)+1))
	if e != nil || count > 128<<20 {
		out.Close()
		return ErrPersistence
	}
	expected := r.UnitSHA256
	if c.Area == "program" {
		expected = p.Input.BinarySHA256
		if c.Name == "ca.pem" {
			expected = p.Input.CASHA256
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		out.Close()
		return ErrConflict
	}
	if rootFile(n, mode) != nil || out.Sync() != nil {
		out.Close()
		return ErrPersistence
	}
	if out.Close() != nil {
		return ErrPersistence
	}
	if closeSource {
		if f.Close() != nil {
			return ErrPersistence
		}
		closeSource = false
	}
	e = unix.Renameat2(fd, tmp, fd, c.Name, unix.RENAME_NOREPLACE)
	if errors.Is(e, unix.EEXIST) {
		return ErrConflict
	}
	if errors.Is(e, unix.ENOSYS) || errors.Is(e, unix.EINVAL) || errors.Is(e, unix.ENOTSUP) {
		return ErrUnsupported
	}
	if e != nil || unix.Fsync(fd) != nil {
		return ErrPersistence
	}
	return nil
}

func checkedCASource(path, expected string) (*os.File, error) {
	f, e := rootSource(path)
	if e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		f.Close()
		return nil, ErrPlan
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != expected {
		f.Close()
		return nil, ErrConflict
	}
	count := 0
	rest := b
	for len(strings.TrimSpace(string(rest))) != 0 {
		block, left := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			f.Close()
			return nil, ErrPlan
		}
		if _, e = x509.ParseCertificate(block.Bytes); e != nil {
			f.Close()
			return nil, ErrPlan
		}
		count++
		rest = left
	}
	if count == 0 {
		f.Close()
		return nil, ErrPlan
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		f.Close()
		return nil, ErrPersistence
	}
	return f, nil
}
