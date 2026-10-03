//go:build darwin

package macosservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func (f *darwinFS) publish(p string, old *node, b []byte) (n node, err error) {
	l := paths(f.target)
	if p != l.Journal && p != l.Control && p != launchPath(l) || p == l.Control && (old != nil || len(b) != 0) {
		return node{}, ErrUnsafe
	}
	fd, name, e := f.parent(p)
	if e != nil {
		return node{}, e
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	return publishAt(fd, name, old, b, 0, 0)
}

// 随机 stage 不参与授权或恢复；崩溃留下的未知/截断 stage 保留且不阻止新重试。
func publishAt(fd int, name string, old *node, b []byte, uid, gid uint32) (node, error) {
	return publishAtSteps(fd, name, old, b, uid, gid, nil)
}
func publishAtSteps(fd int, name string, old *node, b []byte, uid, gid uint32, after func(string)) (n node, err error) {
	step := func(name string) {
		if after != nil {
			after(name)
		}
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return n, e
	}
	tmp := "." + name + ".stage." + hex.EncodeToString(nonce[:])
	child, e := unix.Openat(fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return n, e
	}
	file := os.NewFile(uintptr(child), tmp)
	defer func() { err = errors.Join(err, file.Close()) }()
	n, e = statFD(child)
	if e != nil {
		return n, e
	}
	created := n
	published := false
	defer func() {
		if err != nil && !published {
			err = errors.Join(err, removeAt(fd, tmp, created))
		}
	}()
	if n.Kind != regular || n.UID != uid || n.Links != 1 || n.ACL {
		return n, ErrUnknown
	}
	if e = unix.Fchown(child, int(uid), int(gid)); e != nil {
		return n, e
	}
	if e = unix.Fchmod(child, 0600); e != nil {
		return n, e
	}
	created, e = statFD(child)
	if e != nil {
		return n, e
	}
	step("created")
	if _, e = file.Write(b); e != nil {
		return n, e
	}
	step("written")
	if e = file.Sync(); e != nil {
		return n, e
	}
	step("file-synced")
	current, e := inspectAt(fd, name)
	if old == nil {
		if !errors.Is(e, os.ErrNotExist) {
			return n, ErrConflict
		}
	} else if e != nil || !equalNode(current, *old) || current.UID != uid || current.GID != gid || current.Mode != 0600 || current.Links != 1 || current.ACL {
		return n, ErrUnknown
	}
	stage, e := inspectAt(fd, tmp)
	if e != nil || !equalNode(stage, created) {
		return n, ErrUnknown
	}
	if old == nil {
		e = unix.RenameatxNp(fd, tmp, fd, name, unix.RENAME_EXCL)
	} else {
		e = unix.Renameat(fd, tmp, fd, name)
	}
	if e != nil {
		return n, e
	}
	published = true
	step("renamed")
	n, e = inspectAt(fd, name)
	if e != nil || !equalNode(n, created) {
		return n, ErrUnknown
	}
	if e = unix.Fsync(fd); e != nil {
		return n, e
	}
	step("directory-synced")
	return n, nil
}
func (f *darwinFS) durable(p string, expected node) (err error) {
	if p != paths(f.target).Journal && p != launchPath(paths(f.target)) {
		return ErrUnsafe
	}
	fd, name, e := f.parent(p)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	child, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, unix.Close(child)) }()
	n, e := statFD(child)
	if e != nil || !equalNode(n, expected) || n.Kind != regular || n.UID != 0 || n.GID != 0 || n.Mode != 0600 || n.Links != 1 || n.ACL {
		return ErrUnknown
	}
	if e = unix.Fsync(child); e != nil {
		return e
	}
	return unix.Fsync(fd)
}

func localCommand(ctx context.Context, l layout, t Target, args []string) *exec.Cmd {
	c := safeCommand(ctx, l.Binary, args...)
	c.Dir = l.State
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: t.UID, Gid: t.GID, Groups: []uint32{}}}
	return c
}

// 两条共享本地命令都明确降为目标身份，不加载 CA、不使用网络/宿主环境。
func localResult(ctx context.Context, l layout, t Target, command string, flag string, field string) error {
	args := []string{command}
	if flag != "" {
		args = append(args, flag)
	}
	args = append(args, "--local-directory", l.State, "--local-user", strconv.FormatUint(uint64(t.UID), 10))
	c := localCommand(ctx, l, t, args)
	pipe, e := c.StdoutPipe()
	if e != nil {
		return ErrUnknown
	}
	if e = c.Start(); e != nil {
		return ErrUnknown
	}
	b, readErr := io.ReadAll(io.LimitReader(pipe, 4097))
	closeErr := pipe.Close()
	waitErr := c.Wait()
	if readErr != nil || closeErr != nil || waitErr != nil || len(b) > 4096 {
		return ErrUnknown
	}
	if !bytes.Equal(b, []byte("{\"version\":1,\""+field+"\":true}\n")) {
		return ErrUnknown
	}
	return nil
}
func (darwinRunner) offlineLogout(ctx context.Context, l layout, t Target) error {
	return localResult(ctx, l, t, "logout", "--offline-local", "localLogoutComplete")
}
func (darwinRunner) enrollmentCheck(ctx context.Context, l layout, t Target) error {
	return localResult(ctx, l, t, "local-enrollment-check", "", "localEnrollmentVerified")
}
