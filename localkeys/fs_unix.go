//go:build darwin || linux

package localkeys

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type unixFS struct {
	dir  int
	lock *os.File
	uid  uint32
}

func CurrentUserID() (string, error) {
	if os.Getuid() != os.Geteuid() {
		return "", ErrIdentity
	}
	return strconv.Itoa(os.Geteuid()), nil
}
func openSecureFS(c Config) (secureFS, string, error) {
	return openUnixSecureFS(c, false)
}
func openUnixSecureFS(c Config, existingOnly bool) (secureFS, string, error) {
	owner, err := CurrentUserID()
	if err != nil {
		return nil, "", err
	}
	if owner != c.UserID || c.ServiceSID != "" || owner == "0" {
		return nil, "", ErrIdentity
	}
	if !filepath.IsAbs(c.Directory) || filepath.Clean(c.Directory) != c.Directory || c.Directory == "/" {
		return nil, "", ErrPermission
	}
	uid64, err := strconv.ParseUint(owner, 10, 32)
	if err != nil {
		return nil, "", ErrIdentity
	}
	uid := uint32(uid64)
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(strings.TrimPrefix(c.Directory, "/"), "/")
	for index, part := range parts {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if !existingOnly && errors.Is(err, unix.ENOENT) && index == len(parts)-1 {
			if err = unix.Mkdirat(fd, part, 0700); err == nil {
				if err = unix.Fsync(fd); err == nil {
					next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				}
			}
		}
		unix.Close(fd)
		if err != nil {
			return nil, "", ErrPermission
		}
		fd = next
		var info unix.Stat_t
		if err := unix.Fstat(fd, &info); err != nil {
			unix.Close(fd)
			return nil, "", err
		}
		if info.Uid != 0 && info.Uid != uid {
			unix.Close(fd)
			return nil, "", ErrPermission
		}
		if index == len(parts)-1 {
			if info.Uid != uid || info.Mode&0777 != 0700 {
				unix.Close(fd)
				return nil, "", ErrPermission
			}
			if err := checkExtendedACL(fd, true); err != nil {
				unix.Close(fd)
				return nil, "", err
			}
		}
	}
	fs := &unixFS{dir: fd, uid: uid}
	lockFlags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if !existingOnly {
		lockFlags |= unix.O_CREAT
	}
	lockfd, err := unix.Openat(fd, "vault.lock", lockFlags, 0600)
	if err != nil {
		unix.Close(fd)
		return nil, "", ErrPermission
	}
	fs.lock = os.NewFile(uintptr(lockfd), "vault.lock")
	if err := fs.validate(lockfd); err != nil {
		fs.lock.Close()
		unix.Close(fd)
		return nil, "", err
	}
	if err := unix.Flock(lockfd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		fs.lock.Close()
		unix.Close(fd)
		return nil, "", ErrBusy
	}
	return fs, owner, nil
}
func (f *unixFS) validate(fd int) error {
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != f.uid || info.Mode&0777 != 0600 || info.Nlink != 1 {
		return ErrPermission
	}
	return checkExtendedACL(fd, false)
}
func (f *unixFS) guard() error {
	var directory, lock, current unix.Stat_t
	if err := unix.Fstat(f.dir, &directory); err != nil {
		return err
	}
	if directory.Uid != f.uid || directory.Mode&0777 != 0700 {
		return ErrPermission
	}
	if err := checkExtendedACL(f.dir, true); err != nil {
		return err
	}
	if err := f.validate(int(f.lock.Fd())); err != nil {
		return err
	}
	if err := unix.Fstat(int(f.lock.Fd()), &lock); err != nil {
		return err
	}
	if err := unix.Fstatat(f.dir, "vault.lock", &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return ErrPermission
	}
	if current.Dev != lock.Dev || current.Ino != lock.Ino {
		return ErrPermission
	}
	return nil
}
func (f *unixFS) open(name string) (*os.File, error) {
	fd, err := unix.Openat(f.dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, ErrPermission
	}
	if err := f.validate(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func (f *unixFS) Read(name string, max int) ([]byte, error) {
	if err := f.guard(); err != nil {
		return nil, err
	}
	file, err := f.open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > int64(max) {
		return nil, ErrCorrupt
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, ErrCorrupt
	}
	return data, nil
}
func (f *unixFS) Write(name string, data []byte, exclusive bool) error {
	if err := f.guard(); err != nil {
		return err
	}
	if existing, err := f.open(name); err == nil {
		existing.Close()
		if exclusive {
			return os.ErrExist
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return err
	}
	tmp := ".localkeys-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(f.dir, tmp, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), tmp)
	defer unix.Unlinkat(f.dir, tmp, 0)
	fail := func(err error) error { file.Close(); return err }
	if err := f.validate(fd); err != nil {
		return fail(err)
	}
	if _, err := file.Write(data); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	if exclusive {
		// linkat 提供原子 create-if-absent，不会替换已经存在的机器钥。
		if err := unix.Linkat(f.dir, tmp, f.dir, name, 0); err != nil {
			return err
		}
		if err := unix.Unlinkat(f.dir, tmp, 0); err != nil {
			return err
		}
	} else {
		if err := unix.Renameat(f.dir, tmp, f.dir, name); err != nil {
			return err
		}
	}
	return unix.Fsync(f.dir)
}
func (f *unixFS) Delete(name string) error {
	if err := f.guard(); err != nil {
		return err
	}
	file, err := f.open(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	file.Close()
	if err := unix.Unlinkat(f.dir, name, 0); err != nil {
		return err
	}
	return unix.Fsync(f.dir)
}
func (f *unixFS) Close() error {
	if f.lock == nil {
		return nil
	}
	err := unix.Flock(int(f.lock.Fd()), unix.LOCK_UN)
	err = errors.Join(err, f.lock.Close(), unix.Close(f.dir))
	f.lock = nil
	return err
}
func protectorName() string { return "service-readable-software-key-v1" }
func protectMachineKey(key []byte, c Config, owner string) ([]byte, error) {
	return append([]byte(nil), key...), nil
}
func unprotectMachineKey(data []byte, c Config, owner string) ([]byte, error) {
	return append([]byte(nil), data...), nil
}
