package platform

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// writePrivateFile 原子替换工具自己的文件；拒绝符号链接及其他程序的文件。
func writePrivateFile(path string, data []byte, marker []byte) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private directory is not a real directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("directory must be private (0700)")
	}
	if old, err := os.Lstat(path); err == nil {
		if !old.Mode().IsRegular() || old.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse to replace non-regular file")
		}
		if runtime.GOOS != "windows" && old.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("existing file is not private")
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(content, marker) {
			return fmt.Errorf("refuse to replace a file not owned by Harmonia")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(dir, ".harmonia-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		if err := d.Sync(); err != nil {
			return err
		}
	}
	return nil
}
