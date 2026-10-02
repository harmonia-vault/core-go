//go:build !windows

package localstate

import (
	"errors"
	"os"
	"syscall"
)

func lockFile(f *os.File) error   { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
func privateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must be a real directory")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be private (0700)")
	}
	return nil
}
func privateFile(info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("local cache file must be private (0600)")
	}
	return nil
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
