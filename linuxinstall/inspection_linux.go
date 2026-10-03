//go:build linux

package linuxinstall

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func directoryNames(fd int) ([]string, error) {
	dup, e := unix.Dup(fd)
	if e != nil {
		return nil, ErrPermission
	}
	if _, e = unix.Seek(dup, 0, 0); e != nil {
		unix.Close(dup)
		return nil, ErrPermission
	}
	f := os.NewFile(uintptr(dup), "bounded-directory")
	names, e := f.Readdirnames(1025)
	closeErr := f.Close()
	if e != nil && !errors.Is(e, io.EOF) || closeErr != nil || len(names) > 1024 {
		return nil, ErrState
	}
	return names, nil
}

// checkSystemdNamespace does not follow links or delete vendor units/drop-ins/aliases.
func (l layout) checkSystemdNamespace(p Plan, allowUnit, allowLink bool) error {
	roots := []string{"/etc/systemd/system", "/etc/systemd/system.control", "/run/systemd/system", "/run/systemd/system.control", "/run/systemd/transient", "/run/systemd/generator", "/run/systemd/generator.early", "/run/systemd/generator.late", "/usr/lib/systemd/system", "/usr/local/lib/systemd/system"}
	// Ubuntu merged-/usr has a root-owned /lib -> usr/lib alias. Only that exact
	// canonical duplicate is skipped; an actual /lib tree is separately inspected.
	libParent, e := openDirectory(l.path("/"))
	if e != nil {
		return e
	}
	lib, e := observeAt(libParent, "lib", "system-library")
	ce := unix.Close(libParent)
	if ce != nil {
		return ErrPersistence
	}
	if e == nil {
		if lib.Kind == "directory" {
			roots = append(roots, "/lib/systemd/system")
		} else if lib.Kind != "symlink" || lib.UID != 0 || lib.GID != 0 || lib.Links != 1 || (lib.LinkTarget != "usr/lib" && lib.LinkTarget != "/usr/lib") {
			return ErrConflict
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	for _, root := range roots {
		fd, e := openDirectory(l.path(root))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		e = l.inspectSystemdDirectory(fd, root, p, allowUnit, allowLink, true)
		ce := unix.Close(fd)
		if e != nil {
			return e
		}
		if ce != nil {
			return ErrPersistence
		}
	}
	return nil
}
func (l layout) inspectSystemdDirectory(fd int, path string, p Plan, allowUnit, allowLink, descend bool) error {
	if rootDir(fd, 0755) != nil {
		return ErrPermission
	}
	names, e := directoryNames(fd)
	if e != nil {
		return e
	}
	for _, name := range names {
		var st unix.Stat_t
		if unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return ErrPermission
		}
		actual := filepath.Join(path, name)
		if name == p.UnitName || name == p.UnitName+".d" {
			if actual == p.UnitPath && allowUnit && st.Mode&unix.S_IFMT == unix.S_IFREG {
				continue
			}
			if actual == p.EnableLink && allowLink && st.Mode&unix.S_IFMT == unix.S_IFLNK {
				i, e := observeAt(fd, name, "enable-link")
				if e != nil || i.validate(p) != nil {
					return ErrConflict
				}
				continue
			}
			return ErrConflict
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			b := make([]byte, 4097)
			n, e := unix.Readlinkat(fd, name, b)
			if e != nil || n > 4096 {
				return ErrPermission
			}
			if filepath.Base(string(b[:n])) == p.UnitName {
				return ErrConflict
			}
		}
		if descend && st.Mode&unix.S_IFMT == unix.S_IFDIR && (strings.HasSuffix(name, ".wants") || strings.HasSuffix(name, ".requires")) {
			child, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				return ErrPermission
			}
			e = l.inspectSystemdDirectory(child, actual, p, allowUnit, allowLink, false)
			ce := unix.Close(child)
			if e != nil {
				return e
			}
			if ce != nil {
				return ErrPersistence
			}
		}
	}
	return nil
}
func (l layout) prepare() error {
	for _, path := range []string{"/", "/usr", "/usr/local", "/usr/local/lib", "/etc", "/etc/systemd", "/etc/systemd/system", "/var", "/var/lib"} {
		actual := l.path(path)
		if path == "/" && l.prefix == "" {
			actual = "/"
		}
		fd, e := openDirectory(actual)
		if e != nil {
			return e
		}
		e = rootDir(fd, 0755)
		ce := unix.Close(fd)
		if e != nil {
			return e
		}
		if ce != nil {
			return ErrPersistence
		}
	}
	for _, item := range []struct {
		path string
		mode uint32
	}{{"/usr/local/lib/harmonia", 0755}, {"/var/lib/harmonia", 0755}, {AdminDirectory, 0700}, {"/etc/systemd/system/multi-user.target.wants", 0755}} {
		if e := l.ensureShared(item.path, item.mode); e != nil {
			return e
		}
	}
	return nil
}
func (l layout) verifyCreation(r Receipt, c Creation) (Identity, error) {
	i, e := l.observe(r.Plan, c.Area, c.Name)
	if e != nil {
		return Identity{}, e
	}
	if c.Observed != nil && !sameInode(i, *c.Observed) {
		return Identity{}, ErrConflict
	}
	if c.Area == "state-directory" {
		uid, _ := parseUID(r.Plan.Input.UID)
		gid, _ := parseUID(r.Plan.Input.GID)
		if i.Kind != "directory" || i.Mode != 0700 || i.UID != 0 && (!r.HandoffIntent || i.UID != uid || i.GID != gid) || i.UID == 0 && i.GID != 0 {
			return Identity{}, ErrPermission
		}
	} else if c.Area == "program-directory" {
		if i.Kind != "directory" || i.UID != 0 || i.GID != 0 || i.Mode != 0700 && (!r.HandoffIntent || i.Mode != 0755) {
			return Identity{}, ErrPermission
		}
	} else {
		if i.validate(r.Plan) != nil {
			return Identity{}, ErrPermission
		}
		path, _ := targetPath(r.Plan, c.Area, c.Name)
		sha := r.UnitSHA256
		mode := uint32(0644)
		if c.Area == "program" {
			sha = r.Plan.Input.BinarySHA256
			mode = 0755
			if c.Name == "ca.pem" {
				sha = r.Plan.Input.CASHA256
				mode = 0644
			}
		}
		if e = l.hashFile(path, sha, mode); e != nil {
			return Identity{}, e
		}
	}
	return i, nil
}
func (l layout) verifyReceipt(r Receipt) error {
	if r.Validate() != nil || r.Revision == 0 {
		return ErrState
	}
	for _, c := range r.Creations {
		if c.Observed == nil {
			return ErrState
		}
		if _, e := l.verifyCreation(r, c); e != nil {
			return e
		}
	}
	if r.EnableIdentity != nil {
		i, e := l.observe(r.Plan, "enable-link", r.Plan.UnitName)
		if e != nil || i != *r.EnableIdentity {
			return ErrConflict
		}
	}
	return l.checkSystemdNamespace(r.Plan, true, r.EnableIntent)
}
