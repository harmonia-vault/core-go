//go:build linux

package linuxinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func openInstalledBinary(p Plan) (*os.File, error) {
	if p.Validate() != nil || rootIdentity() != nil {
		return nil, ErrPermission
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrPermission
	}
	for _, part := range strings.Split(strings.TrimPrefix(p.ProgramDirectory, "/"), "/") {
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
	bin, err := unix.Openat(fd, "harmonia", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	unix.Close(fd)
	if err != nil {
		return nil, ErrPermission
	}
	f := os.NewFile(uintptr(bin), "harmonia")
	if rootFile(bin, 0755) != nil {
		f.Close()
		return nil, ErrPermission
	}
	size, e := unix.Fgetxattr(bin, "security.capability", nil)
	if e == nil && size > 0 || e != nil && !errors.Is(e, unix.ENODATA) && !errors.Is(e, unix.ENOTSUP) {
		f.Close()
		return nil, ErrPermission
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if err != nil || n > 128<<20 || hex.EncodeToString(h.Sum(nil)) != p.Input.BinarySHA256 {
		f.Close()
		return nil, ErrConflict
	}
	return f, nil
}

// RunOfflineLogout 只完成共享 CLI 的实际 localLogoutComplete 回执。
// 最终 freeze/relock/account-slot 缺失检查和删除协调器不能据此被跳过。
// 卸载协调器在正常 drain 后调用；调用者须仍持有本实例 root 管理 lease。
func (l *AdminLease) RunOfflineLogout(ctx context.Context, p Plan) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.guard() != nil || p.Validate() != nil || p.Input.UID != l.uid {
		return ErrPermission
	}
	b, err := l.read(l.uid + ".installation.json")
	if err != nil {
		return err
	}
	r, err := DecodeReceipt(b)
	if err != nil || r.Plan != p {
		return ErrState
	}
	b, err = l.read(l.uid + ".uninstall.json")
	if err != nil {
		return err
	}
	j, err := DecodeJournal(b)
	if err != nil || j.Plan != p || j.InstallationID != r.InstallationID || j.Phase != "service-drained" && j.Phase != "offline-closed" {
		return ErrState
	}
	b, err = l.read(l.uid + ".uninstalling")
	if err != nil || !bytes.Equal(b, []byte(r.InstallationID+"\n")) {
		return ErrState
	}
	u, err := user.Lookup(p.Input.UserName)
	if err != nil || u.Uid != p.Input.UID || u.Gid != p.Input.GID {
		return ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err = CheckDrained(ctx, p); err != nil {
		return err
	}
	f, err := openInstalledBinary(p)
	if err != nil {
		return err
	}
	defer f.Close()
	if l.guard() != nil {
		return ErrPermission
	}
	uid, err := parseUID(p.Input.UID)
	if err != nil {
		return err
	}
	gid, err := parseUID(p.Input.GID)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, p.BinaryPath, "logout", "--offline-local", "--local-directory", p.StateDirectory, "--local-user", p.Input.UID)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}, NoSetGroups: false}}
	var out = boundedOutput{limit: maxLocalCompletionBytes}
	var discard = boundedOutput{limit: maxLocalCompletionBytes}
	cmd.Stdout = &out
	cmd.Stderr = &discard
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrState
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = l.guard(); err != nil {
		return err
	}
	if f.Close() != nil {
		return ErrPersistence
	}
	return decodeLocalCompletion(out.b.Bytes())
}
