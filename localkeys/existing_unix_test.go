//go:build darwin || linux

package localkeys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func existingConfig(t *testing.T) Config {
	t.Helper()
	uid, e := CurrentUserID()
	if e != nil || uid == "0" {
		t.Skip("需要普通 Unix 合成文件所有者")
	}
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return Config{Directory: filepath.Join(parent, "vault"), UserID: uid}
}
func TestExistingOnlyNeverCreatesMissingDirectoryLockOrKey(t *testing.T) {
	for _, which := range []string{"directory", "lock", "key"} {
		t.Run(which, func(t *testing.T) {
			c := existingConfig(t)
			if which != "directory" {
				if e := os.Mkdir(c.Directory, 0700); e != nil {
					t.Fatal(e)
				}
			}
			if which == "key" {
				if e := os.WriteFile(filepath.Join(c.Directory, "vault.lock"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if v, e := OpenExisting(c); e == nil {
				v.Close()
				t.Fatal("缺材料被重新初始化")
			}
			if which == "directory" {
				if _, e := os.Lstat(c.Directory); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("创建了目录", e)
				}
				return
			}
			xs, e := os.ReadDir(c.Directory)
			if e != nil {
				t.Fatal(e)
			}
			want := 0
			if which == "key" {
				want = 1
			}
			if len(xs) != want {
				t.Fatal("创建了锁/机器钥", xs)
			}
		})
	}
}
func TestExistingOnlyUsesRealOwnerLockAndRejectsUnsafeExistingFiles(t *testing.T) {
	c := existingConfig(t)
	v, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := OpenExisting(c); !errors.Is(e, ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("未排除运行 owner", e)
	}
	if e = v.Close(); e != nil {
		t.Fatal(e)
	}
	v, e = OpenExisting(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = v.Close(); e != nil {
		t.Fatal(e)
	}
	for _, which := range []string{"lockMode", "keyMode", "keyLink", "lockSymlink", "wrongIdentity"} {
		t.Run(which, func(t *testing.T) {
			c := existingConfig(t)
			v, e := Open(c)
			if e != nil {
				t.Fatal(e)
			}
			if e = v.Close(); e != nil {
				t.Fatal(e)
			}
			switch which {
			case "lockMode":
				e = os.Chmod(filepath.Join(c.Directory, "vault.lock"), 0644)
			case "keyMode":
				e = os.Chmod(filepath.Join(c.Directory, keyFile), 0644)
			case "keyLink":
				e = os.Link(filepath.Join(c.Directory, keyFile), filepath.Join(c.Directory, "other"))
			case "lockSymlink":
				e = os.Rename(filepath.Join(c.Directory, "vault.lock"), filepath.Join(c.Directory, "other"))
				if e == nil {
					e = os.Symlink("other", filepath.Join(c.Directory, "vault.lock"))
				}
			case "wrongIdentity":
				c.UserID = "0"
			}
			if e != nil {
				t.Fatal(e)
			}
			if other, e := OpenExisting(c); e == nil {
				other.Close()
				t.Fatal("不安全已有材料被接受")
			}
		})
	}
}
