//go:build darwin

package macosservice

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// 所有未引用stage都放可信共享父目录，不能污染最终program精确集合。
func (f *darwinFS) prepareCreation(p, parent string, b []byte, uid, gid, mode uint32, dir bool) (x creation, err error) {
	stageFD, e := f.openDir(parent)
	if e != nil {
		return x, e
	}
	defer func() { err = errors.Join(err, unix.Close(stageFD)) }()
	finalFD, _, e := f.parent(p)
	if e != nil {
		return x, e
	}
	defer func() { err = errors.Join(err, unix.Close(finalFD)) }()
	x.Parent, e = statFD(stageFD)
	if e != nil {
		return x, e
	}
	x.FinalParent, e = statFD(finalFD)
	if e != nil {
		return x, e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return x, e
	}
	x.Stage = ".harmonia." + filepath.Base(paths(f.target).Program) + ".stage." + hex.EncodeToString(nonce[:])
	var child int
	if dir {
		if e = unix.Mkdirat(stageFD, x.Stage, 0700); e != nil {
			return x, e
		}
		child, e = unix.Openat(stageFD, x.Stage, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	} else {
		child, e = unix.Openat(stageFD, x.Stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	}
	if e != nil {
		return x, e
	}
	file := os.NewFile(uintptr(child), x.Stage)
	defer func() { err = errors.Join(err, file.Close()) }()
	n, e := statFD(child)
	if e != nil || n.UID != 0 || n.ACL || (dir && n.Kind != directory) || (!dir && (n.Kind != regular || n.Links != 1)) {
		return x, ErrUnknown
	}
	if !dir {
		if written, we := file.Write(b); we != nil || written != len(b) {
			e = errors.Join(we, io.ErrShortWrite)
			return x, e
		}
		x.Hash = digest(b)
	}
	if e = unix.Fchown(child, int(uid), int(gid)); e != nil {
		return x, e
	}
	if e = unix.Fchmod(child, mode); e != nil {
		return x, e
	}
	if e = file.Sync(); e != nil {
		return x, e
	}
	x.Node, e = statFD(child)
	if e != nil || x.Node.UID != uid || x.Node.GID != gid || x.Node.Mode != mode || x.Node.ACL {
		return x, ErrUnknown
	}
	// 返回前同步stage名字；正常错误也不猜删未记录项，保持inert边界。
	return x, unix.Fsync(stageFD)
}
func (f *darwinFS) commitCreation(p, parent string, x creation) (err error) {
	stageFD, e := f.openDir(parent)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, unix.Close(stageFD)) }()
	finalFD, name, e := f.parent(p)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, unix.Close(finalFD)) }()
	return f.commitCreationAt(stageFD, finalFD, name, x)
}

// root祖先的核验由上层openDir完成；本层只在已持有可信FD下核精确父/对象身份。
func (f *darwinFS) commitCreationAt(stageFD, finalFD int, name string, x creation) error {
	sn, e := statFD(stageFD)
	if e != nil || !equalNode(sn, x.Parent) {
		return ErrUnknown
	}
	fn, e := statFD(finalFD)
	if e != nil || !equalNode(fn, x.FinalParent) {
		return ErrUnknown
	}
	stage, se := inspectAt(stageFD, x.Stage)
	final, fe := inspectAt(finalFD, name)
	if fe == nil {
		if !equalNode(final, x.Node) || !errors.Is(se, os.ErrNotExist) {
			return ErrUnknown
		}
		if x.Node.Kind == regular {
			if e = f.creationContentAt(finalFD, name, x); e != nil {
				return e
			}
		}
		if e = unix.Fsync(stageFD); e != nil {
			return e
		}
		return unix.Fsync(finalFD)
	}
	if !errors.Is(fe, os.ErrNotExist) || se != nil || !equalNode(stage, x.Node) {
		return ErrUnknown
	}
	if x.Node.Kind == regular {
		if e = f.creationContentAt(stageFD, x.Stage, x); e != nil {
			return e
		}
	}
	if e = unix.RenameatxNp(stageFD, x.Stage, finalFD, name, unix.RENAME_EXCL); e != nil {
		return e
	}
	published, e := inspectAt(finalFD, name)
	if e != nil || !equalNode(published, x.Node) {
		return ErrUnknown
	}
	if e = unix.Fsync(finalFD); e != nil {
		return e
	}
	return unix.Fsync(stageFD)
}

func (f *darwinFS) creationContentAt(parent int, name string, x creation) (err error) {
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { err = errors.Join(err, file.Close()) }()
	n, e := statFD(fd)
	if e != nil || !equalNode(n, x.Node) {
		return ErrUnknown
	}
	b, e := io.ReadAll(io.LimitReader(file, (128<<20)+1))
	if e != nil || len(b) > 128<<20 || digest(b) != x.Hash {
		return ErrUnknown
	}
	after, e := statFD(fd)
	if e != nil || !equalNode(after, x.Node) {
		return ErrUnknown
	}
	return nil
}

func (f *darwinFS) childrenCreated(p string, expected node) (xs []entry, err error) {
	parent, name, e := f.parent(p)
	if e != nil {
		return nil, e
	}
	defer func() { err = errors.Join(err, unix.Close(parent)) }()
	return childrenCreatedAt(parent, name, expected)
}
func childrenCreatedAt(parent int, name string, expected node) (xs []entry, err error) {
	child, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(child), name)
	defer func() { err = errors.Join(err, file.Close()) }()
	n, e := statFD(child)
	if e != nil || !equalNode(n, expected) || n.Kind != directory {
		return nil, ErrUnknown
	}
	names, e := file.Readdirnames(129)
	if len(names) > 128 {
		return nil, ErrUnknown
	}
	if errors.Is(e, io.EOF) {
		e = nil
	}
	if e != nil {
		return nil, e
	}
	for _, name := range names {
		n, e := inspectAt(child, name)
		if e != nil {
			return nil, e
		}
		xs = append(xs, entry{Name: name, Node: n})
	}
	after, e := statFD(child)
	if e != nil || !equalNode(after, expected) {
		return nil, ErrUnknown
	}
	return xs, nil
}
