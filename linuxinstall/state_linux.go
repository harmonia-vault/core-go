//go:build linux

package linuxinstall

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sort"
)

type frozenState struct {
	fs                     layout
	p                      Plan
	state, ipc             int
	locks                  []int
	empty                  bool
	absent                 bool
	stateFrozen, ipcFrozen bool
	thawUID, thawGID       uint32
}

func validUserObject(i Identity, uid, gid uint32, kind string) bool {
	return i.UID == uid && i.GID == gid && i.Kind == kind && i.Mode == 0600 && (kind == "socket" || i.Links == 1) && i.LinkTarget == ""
}
func (f *frozenState) scan(final bool) error {
	names, e := directoryNames(f.state)
	if e != nil {
		return e
	}
	uid, _ := parseUID(f.p.Input.UID)
	gid, _ := parseUID(f.p.Input.GID)
	for _, name := range names {
		if name == "ipc" {
			i, e := observeAt(f.state, name, "ipc-directory")
			if e != nil || i.Kind != "directory" || i.Mode != 0700 || i.UID != 0 && (i.UID != uid || i.GID != gid) || i.UID == 0 && i.GID != 0 {
				return ErrPermission
			}
			continue
		}
		if !stateNames[name] && !accountNames[name] {
			return ErrConflict
		}
		i, e := observeAt(f.state, name, "state")
		if e != nil || !validUserObject(i, uid, gid, "file") {
			return ErrPermission
		}
		if final && accountNames[name] {
			return ErrConflict
		}
	}
	if f.ipc >= 0 {
		names, e = directoryNames(f.ipc)
		if e != nil {
			return e
		}
		for _, name := range names {
			kind, ok := ipcNames[name]
			if !ok {
				return ErrConflict
			}
			i, e := observeAt(f.ipc, name, "ipc")
			if e != nil || !validUserObject(i, uid, gid, kind) {
				return ErrPermission
			}
		}
	}
	return nil
}
func openUserLock(fd int, name string, uid, gid uint32) (int, error) {
	n, e := unix.Openat(fd, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, ErrState
	}
	var st unix.Stat_t
	if unix.Fstat(n, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uid || st.Gid != gid || st.Nlink != 1 || checkACL(n, false) != nil {
		unix.Close(n)
		return -1, ErrPermission
	}
	if e = unix.Flock(n, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		unix.Close(n)
		if errors.Is(e, unix.EWOULDBLOCK) || errors.Is(e, unix.EAGAIN) {
			return -1, ErrBusy
		}
		return -1, ErrPermission
	}
	return n, nil
}
func freezeDirectory(fd int) error {
	if unix.Fchown(fd, 0, 0) != nil || unix.Fchmod(fd, 0700) != nil || unix.Fsync(fd) != nil {
		return ErrPersistence
	}
	return nil
}
func (c *coordinator) freezeState(r Receipt) (*frozenState, error) {
	f := &frozenState{fs: c.fs, p: r.Plan, state: -1, ipc: -1}
	var expected *Identity
	for _, o := range r.Creations {
		if o.Area == "state-directory" {
			expected = o.Observed
		}
	}
	if expected == nil {
		_, e := c.fs.observe(r.Plan, "state-directory", r.Plan.Input.UID)
		if !errors.Is(e, os.ErrNotExist) {
			return nil, ErrConflict
		}
		f.absent = true
		f.empty = true
		return f, nil
	}
	actual, e := c.fs.observe(r.Plan, "state-directory", r.Plan.Input.UID)
	if e != nil || !sameInode(actual, *expected) {
		return nil, ErrConflict
	}
	uid, _ := parseUID(r.Plan.Input.UID)
	gid, _ := parseUID(r.Plan.Input.GID)
	if actual.Kind != "directory" || actual.Mode != 0700 || actual.UID != 0 && (actual.UID != uid || actual.GID != gid) || actual.UID == 0 && actual.GID != 0 {
		return nil, ErrPermission
	}
	f.state, e = openDirectory(c.fs.path(r.Plan.StateDirectory))
	if e != nil {
		return nil, e
	}
	if !fdMatchesIdentity(f.state, actual) {
		return nil, errors.Join(ErrConflict, f.closeFrozen())
	}
	if r.HandoffIntent {
		f.thawUID = uid
		f.thawGID = gid
	}
	i, e := observeAt(f.state, "ipc", "ipc-directory")
	if e == nil {
		if i.Kind != "directory" || i.Mode != 0700 || i.UID != 0 && (i.UID != uid || i.GID != gid) || i.UID == 0 && i.GID != 0 {
			f.closeFrozen()
			return nil, ErrPermission
		}
		f.ipc, e = unix.Openat(f.state, "ipc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			f.closeFrozen()
			return nil, ErrPermission
		}
		if !fdMatchesIdentity(f.ipc, i) {
			return nil, errors.Join(ErrConflict, f.closeFrozen())
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		f.closeFrozen()
		return nil, e
	}
	if e = f.scan(false); e != nil {
		return nil, errors.Join(e, f.closeFrozen())
	}
	// First block future path opens, then nonblocking-lock any already opened owners.
	f.stateFrozen = true
	if e = freezeDirectory(f.state); e != nil {
		return nil, errors.Join(e, f.restoreAndClose())
	}
	if e = f.checkBindings(); e != nil {
		return nil, errors.Join(e, f.restoreAndClose())
	}
	if f.ipc >= 0 {
		f.ipcFrozen = true
		if e = freezeDirectory(f.ipc); e != nil {
			return nil, errors.Join(e, f.restoreAndClose())
		}
	}
	// Decide genuinely-empty only after namespace freeze, so a concurrent first
	// CLI opener cannot create/hold vault.lock between the empty check and locking.
	names, e := directoryNames(f.state)
	if e != nil {
		return nil, errors.Join(e, f.restoreAndClose())
	}
	f.empty = len(names) == 0
	if !f.empty {
		lock, e := openUserLock(f.state, "vault.lock", uid, gid)
		if e != nil {
			return nil, errors.Join(e, f.restoreAndClose())
		}
		f.locks = append(f.locks, lock)
		if f.ipc >= 0 {
			lock, e = openUserLock(f.ipc, "ipc.lock", uid, gid)
			if e != nil {
				return nil, errors.Join(e, f.restoreAndClose())
			}
			f.locks = append(f.locks, lock)
		}
	}
	if e = f.checkBindings(); e != nil {
		return nil, errors.Join(e, f.restoreAndClose())
	}
	if e = f.scan(false); e != nil {
		return nil, errors.Join(e, f.restoreAndClose())
	}
	return f, nil
}
func (f *frozenState) closeFrozen() error {
	var es []error
	for _, fd := range f.locks {
		es = append(es, unix.Flock(fd, unix.LOCK_UN), unix.Close(fd))
	}
	f.locks = nil
	if f.ipc >= 0 {
		es = append(es, unix.Close(f.ipc))
		f.ipc = -1
	}
	if f.state >= 0 {
		es = append(es, unix.Close(f.state))
		f.state = -1
	}
	return errors.Join(es...)
}
func (f *frozenState) restoreAndClose() error {
	var es []error
	for _, item := range []struct {
		fd      int
		changed bool
	}{{f.ipc, f.ipcFrozen}, {f.state, f.stateFrozen}} {
		if item.fd >= 0 && item.changed {
			if unix.Fchown(item.fd, int(f.thawUID), int(f.thawGID)) != nil || unix.Fchmod(item.fd, 0700) != nil || unix.Fsync(item.fd) != nil {
				es = append(es, ErrPersistence)
			}
		}
	}
	es = append(es, f.closeFrozen())
	return errors.Join(es...)
}
func fdMatchesIdentity(fd int, i Identity) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && uint64(st.Dev) == i.Device && st.Ino == i.Inode && st.Mode&unix.S_IFMT == unix.S_IFDIR
}
func (f *frozenState) checkBindings() error {
	state, e := f.fs.observe(f.p, "state-directory", f.p.Input.UID)
	if e != nil || !fdMatchesIdentity(f.state, state) {
		return ErrConflict
	}
	ipc, e := observeAt(f.state, "ipc", "ipc-directory")
	if f.ipc < 0 {
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		return ErrConflict
	}
	if e != nil || !fdMatchesIdentity(f.ipc, ipc) {
		return ErrConflict
	}
	return nil
}
func (c *coordinator) cleanupObjects(r Receipt, f *frozenState) ([]Identity, error) {
	// Preserve any interrupted copy; resume install first rather than silently deleting it.
	for _, o := range r.Creations {
		if o.Area != "program" && o.Area != "unit" {
			continue
		}
		path, _ := targetPath(r.Plan, o.Area, o.Name)
		fd, e := openDirectory(filepath.Dir(c.fs.path(path)))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return nil, e
		}
		_, e = observeAt(fd, creationTemporaryName(r, o), o.Area)
		ce := unix.Close(fd)
		if !errors.Is(e, os.ErrNotExist) {
			return nil, ErrConflict
		}
		if ce != nil {
			return nil, ErrPersistence
		}
	}

	if !f.absent {
		if e := f.scan(true); e != nil {
			return nil, e
		}
	}
	if e := c.fs.checkSystemdNamespace(r.Plan, creationObserved(r, "unit"), r.EnableIdentity != nil); e != nil {
		return nil, e
	}
	objects := []Identity{}
	if f.ipc >= 0 {
		names, e := directoryNames(f.ipc)
		if e != nil {
			return nil, e
		}
		sort.Strings(names)
		for _, n := range names {
			i, e := observeAt(f.ipc, n, "ipc")
			if e != nil || i.validate(r.Plan) != nil {
				return nil, ErrPermission
			}
			objects = append(objects, i)
		}
		i, e := c.fs.observe(r.Plan, "ipc-directory", "ipc")
		if e != nil || i.validate(r.Plan) != nil {
			return nil, ErrPermission
		}
		objects = append(objects, i)
	}
	if f.state >= 0 {
		names, e := directoryNames(f.state)
		if e != nil {
			return nil, e
		}
		sort.Slice(names, func(i, j int) bool {
			if names[i] == "vault.lock" {
				return false
			}
			if names[j] == "vault.lock" {
				return true
			}
			return names[i] < names[j]
		})
		for _, n := range names {
			if n == "ipc" {
				continue
			}
			i, e := observeAt(f.state, n, "state")
			if e != nil || i.validate(r.Plan) != nil {
				return nil, ErrPermission
			}
			objects = append(objects, i)
		}
		i, e := c.fs.observe(r.Plan, "state-directory", r.Plan.Input.UID)
		if e != nil || i.validate(r.Plan) != nil {
			return nil, ErrPermission
		}
		objects = append(objects, i)
	}
	if r.EnableIdentity != nil {
		i, e := c.fs.observe(r.Plan, "enable-link", r.Plan.UnitName)
		if e != nil || i != *r.EnableIdentity {
			return nil, ErrConflict
		}
		objects = append(objects, i)
	}
	for _, area := range []string{"unit", "program", "program-directory"} {
		for _, o := range r.Creations {
			if o.Area != area || o.Observed == nil {
				continue
			}
			i, e := c.fs.verifyCreation(r, o)
			if e != nil {
				return nil, e
			}
			if i.validate(r.Plan) != nil {
				return nil, ErrPermission
			}
			objects = append(objects, i)
		}
	}
	// Unknown files, including interrupted temporary copies, prevent a directory deletion.
	if creationObserved(r, "program-directory") {
		fd, e := openDirectory(c.fs.path(r.Plan.ProgramDirectory))
		if e != nil {
			return nil, e
		}
		names, e := directoryNames(fd)
		ce := unix.Close(fd)
		if e != nil || ce != nil {
			return nil, ErrPersistence
		}
		for _, n := range names {
			found := false
			for _, o := range r.Creations {
				if o.Area == "program" && o.Observed != nil && o.Name == n {
					found = true
				}
			}
			if !found {
				return nil, ErrConflict
			}
		}
	}
	return objects, nil
}
func deletionIdentityMatches(a, b Identity) bool {
	if a.Kind == "directory" {
		a.Links = b.Links
	}
	return a == b
}
func (l layout) remove(p Plan, i Identity) (resultErr error) {
	path, e := targetPath(p, i.Area, i.Name)
	if e != nil {
		return e
	}
	fd, e := openDirectory(filepath.Dir(l.path(path)))
	if e != nil {
		return e
	}
	defer func() {
		if e := unix.Close(fd); e != nil {
			resultErr = errors.Join(resultErr, ErrPersistence)
		}
	}()
	wantMode := uint32(0755)
	if i.Area == "state" || i.Area == "ipc" || i.Area == "ipc-directory" {
		wantMode = 0700
	}
	if rootDir(fd, wantMode) != nil && !(i.Area == "program" && rootDir(fd, 0700) == nil) {
		return ErrPermission
	}
	current, e := observeAt(fd, i.Name, i.Area)
	if e != nil || !deletionIdentityMatches(current, i) {
		return ErrConflict
	}
	flags := 0
	if i.Kind == "directory" {
		flags = unix.AT_REMOVEDIR
	}
	if unix.Unlinkat(fd, i.Name, flags) != nil || unix.Fsync(fd) != nil {
		return ErrPersistence
	}
	return nil
}

// Authorized retry never thaws a directory or repeats logout. Missing objects require
// their exact durable deletion intent; every remaining object must still be original.
func (c *coordinator) lockAuthorizedState(j Journal) (*frozenState, error) {
	if j.Validate() != nil || journalPhases[j.Phase] < 3 {
		return nil, ErrState
	}
	f := &frozenState{fs: c.fs, p: j.Plan, state: -1, ipc: -1}
	index := map[string]Deletion{}
	for _, d := range j.Deletions {
		index[d.Object.Area+"/"+d.Object.Name] = d
		i, e := c.fs.observe(j.Plan, d.Object.Area, d.Object.Name)
		if errors.Is(e, os.ErrNotExist) {
			if !d.Intent {
				return nil, ErrState
			}
			continue
		}
		if e != nil || d.Removed || !deletionIdentityMatches(i, d.Object) {
			return nil, ErrConflict
		}
	}
	if _, ok := index["state-directory/"+j.Plan.Input.UID]; !ok {
		return f, nil
	}
	fd, e := openDirectory(c.fs.path(j.Plan.StateDirectory))
	if errors.Is(e, os.ErrNotExist) {
		f.absent = true
		return f, nil
	}
	if e != nil {
		return nil, e
	}
	f.state = fd
	if rootDir(fd, 0700) != nil {
		return nil, errors.Join(ErrPermission, f.closeFrozen())
	}
	i, e := observeAt(fd, "ipc", "ipc-directory")
	if e == nil {
		if rootDirIdentity(i) != nil {
			return nil, errors.Join(ErrPermission, f.closeFrozen())
		}
		f.ipc, e = unix.Openat(fd, "ipc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, errors.Join(ErrPermission, f.closeFrozen())
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, errors.Join(e, f.closeFrozen())
	}
	for _, d := range []struct {
		fd         int
		area, name string
	}{{f.state, "state", "vault.lock"}, {f.ipc, "ipc", "ipc.lock"}} {
		if d.fd < 0 {
			continue
		}
		item, ok := index[d.area+"/"+d.name]
		if !ok {
			names, e := directoryNames(d.fd)
			if e != nil || len(names) != 0 {
				return nil, errors.Join(ErrState, f.closeFrozen())
			}
			continue
		}
		_, e := observeAt(d.fd, d.name, d.area)
		if errors.Is(e, os.ErrNotExist) && item.Intent {
			continue
		}
		if e != nil {
			return nil, errors.Join(e, f.closeFrozen())
		}
		uid, _ := parseUID(j.Plan.Input.UID)
		gid, _ := parseUID(j.Plan.Input.GID)
		n, e := openUserLock(d.fd, d.name, uid, gid)
		if e != nil {
			return nil, errors.Join(e, f.closeFrozen())
		}
		f.locks = append(f.locks, n)
	}
	for _, dir := range []struct {
		fd   int
		area string
	}{{f.state, "state"}, {f.ipc, "ipc"}} {
		if dir.fd < 0 {
			continue
		}
		names, e := directoryNames(dir.fd)
		if e != nil {
			return nil, errors.Join(e, f.closeFrozen())
		}
		for _, name := range names {
			if dir.area == "state" && name == "ipc" {
				continue
			}
			d, ok := index[dir.area+"/"+name]
			if !ok || d.Removed {
				return nil, errors.Join(ErrConflict, f.closeFrozen())
			}
		}
	}
	return f, nil
}
func rootDirIdentity(i Identity) error {
	if i.Kind != "directory" || i.UID != 0 || i.GID != 0 || i.Mode != 0700 {
		return ErrPermission
	}
	return nil
}

// Absence after an interrupted unlink is not enough: the actual object parent
// must be re-synced before 'removed' is committed in the separate admin directory.
func (l layout) syncAbsentParent(p Plan, i Identity) error {
	path, e := targetPath(p, i.Area, i.Name)
	if e != nil {
		return e
	}
	fd, e := openDirectory(filepath.Dir(l.path(path)))
	if e != nil {
		return e
	}
	mode := uint32(0755)
	if i.Area == "state" || i.Area == "ipc" || i.Area == "ipc-directory" {
		mode = 0700
	}
	if rootDir(fd, mode) != nil && !(i.Area == "program" && rootDir(fd, 0700) == nil) {
		unix.Close(fd)
		return ErrPermission
	}
	if unix.Fsync(fd) != nil {
		unix.Close(fd)
		return ErrPersistence
	}
	if unix.Close(fd) != nil {
		return ErrPersistence
	}
	return nil
}
