//go:build linux

package linuxinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// These tests require isolated Linux root, use a new temporary layout, and inject
// only system-manager/helper responses. They do NOT prove real enrollment/systemd.
type fixtureRuntime struct {
	fs            layout
	active        bool
	enrollErr     error
	drainErr      error
	logoutHook    func(Plan) error
	controls      []string
	logoutCalls   int
	effectiveType string
	enableType    string
	unitTypeCalls int
}

func (r *fixtureRuntime) show(ctx context.Context, p Plan) (UnitState, error) {
	if ctx.Err() != nil {
		return UnitState{}, ctx.Err()
	}
	s := UnitState{ID: p.UnitName, ActiveState: "inactive", SubState: "dead", Result: "success"}
	_, e := r.fs.observe(p, "unit", p.UnitName)
	if errors.Is(e, os.ErrNotExist) {
		s.LoadState = "not-found"
		return s, nil
	}
	if e != nil {
		return UnitState{}, e
	}
	s.LoadState = "loaded"
	s.FragmentPath = p.UnitPath
	s.UnitFileState = "disabled"
	if _, e = r.fs.observe(p, "enable-link", p.UnitName); e == nil {
		s.UnitFileState = "enabled"
	}
	if r.active {
		s.ActiveState = "active"
		s.SubState = "running"
		s.MainPID = 123
		s.ControlGroup = "/system.slice/" + p.UnitName
	}
	return s, nil
}
func (r *fixtureRuntime) unitType(ctx context.Context, p Plan, expected string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r.unitTypeCalls++
	actual := r.effectiveType
	if actual == "" {
		body, err := os.ReadFile(r.fs.path(p.UnitPath))
		if err != nil {
			return err
		}
		if bytes.Contains(body, []byte("\nType=exec\n")) {
			actual = "exec"
		} else if bytes.Contains(body, []byte("\nType=simple\n")) {
			actual = "simple"
		}
	}
	return decodeUnitType([]byte("Type="+actual+"\n"), expected)
}

func (r *fixtureRuntime) control(ctx context.Context, op string, p Plan) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r.controls = append(r.controls, op)
	switch op {
	case "start":
		r.active = true
	case "stop":
		r.active = false
	case "enable":
		path := r.fs.path(p.EnableLink)
		if e := os.Symlink(p.UnitPath, path); e != nil && !errors.Is(e, os.ErrExist) {
			return e
		}
		if r.enableType != "" {
			r.effectiveType = r.enableType
		}
	}
	return nil
}
func (r *fixtureRuntime) drained(ctx context.Context, p Plan) error {
	if r.drainErr != nil {
		return r.drainErr
	}
	s, e := r.show(ctx, p)
	if e != nil {
		return e
	}
	if !s.NormalStop() {
		return ErrState
	}
	return nil
}
func (r *fixtureRuntime) enrollment(context.Context, Plan) error { return r.enrollErr }
func (r *fixtureRuntime) logout(_ context.Context, p Plan) error {
	r.logoutCalls++
	if r.logoutHook != nil {
		return r.logoutHook(p)
	}
	return nil
}
func nativeFixture(t *testing.T) (*coordinator, Plan, *fixtureRuntime) {
	t.Helper()
	if rootIdentity() != nil {
		t.Skip("isolated Linux root temp directory required")
	}
	u, e := user.Lookup("nobody")
	if e != nil || !decimalID(u.Uid, true) || !decimalID(u.Gid, true) {
		t.Fatal("expected Ubuntu nobody test identity")
	}
	root := t.TempDir()
	if os.Chmod(root, 0755) != nil {
		t.Fatal("root chmod")
	}
	fs := layout{prefix: root}
	for _, path := range []string{"/usr/local/lib", "/etc/systemd/system", "/var/lib"} {
		if e = os.MkdirAll(fs.path(path), 0755); e != nil {
			t.Fatal(e)
		}
	}
	// 只有本测试刚建立的 temp 祖先可显式设置；不依赖调用者 umask，
	// 不修改真实系统目录，也不把未知既有对象交给生产 prepare 修补。
	for _, path := range []string{"/usr", "/usr/local", "/usr/local/lib", "/etc", "/etc/systemd", "/etc/systemd/system", "/var", "/var/lib"} {
		if e = os.Chmod(fs.path(path), 0755); e != nil {
			t.Fatal(e)
		}
	}
	if e = fs.prepare(); e != nil {
		t.Fatal(e)
	}
	parent, e := openDirectory(fs.path("/var/lib"))
	if e != nil {
		t.Fatal(e)
	}
	fd, e := openDirectory(fs.path(AdminDirectory))
	if e != nil {
		t.Fatal(e)
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		t.Fatal("stat")
	}
	store := &AdminStore{dir: fd, parent: parent, dev: uint64(st.Dev), ino: st.Ino}
	lease, e := store.Acquire(u.Uid)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := lease.Close(); e != nil {
			t.Error(e)
		}
		if e := store.Close(); e != nil {
			t.Error(e)
		}
	})
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(executable)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(b)
	source := filepath.Join(root, "explicit-cli-source")
	if e = os.WriteFile(source, b, 0755); e != nil {
		t.Fatal(e)
	}
	p, e := NewPlan(Input{UserName: u.Username, UID: u.Uid, GID: u.Gid, BinarySource: source, BinarySHA256: hex.EncodeToString(h[:])})
	if e != nil {
		t.Fatal(e)
	}
	runtime := &fixtureRuntime{fs: fs}
	return &coordinator{lease: lease, fs: fs, runtime: runtime}, p, runtime
}
func installFixture(t *testing.T, c *coordinator, p Plan) Receipt {
	t.Helper()
	got, e := c.install(context.Background(), p)
	if e != nil || got.Phase != "installed-disabled" {
		t.Fatal("install", e)
	}
	r, e := c.lease.LoadReceipt()
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func writeUserFixture(t *testing.T, c *coordinator, p Plan, name string) {
	t.Helper()
	path := c.fs.path(filepath.Join(p.StateDirectory, name))
	if e := os.WriteFile(path, []byte("synthetic-test-only"), 0600); e != nil {
		t.Fatal(e)
	}
	uid, _ := parseUID(p.Input.UID)
	gid, _ := parseUID(p.Input.GID)
	if e := os.Chown(path, int(uid), int(gid)); e != nil {
		t.Fatal(e)
	}
}
func TestLinuxCoordinatorStagesDisabledRefusesUnknownTrustAndRemovesEmpty(t *testing.T) {
	c, p, runtime := nativeFixture(t)
	installFixture(t, c, p)
	runtime.enrollErr = ErrState
	if _, e := c.start(context.Background()); e != ErrState {
		t.Fatal("unverified start not rejected", e)
	}
	for _, op := range runtime.controls {
		if op == "enable" || op == "start" {
			t.Fatal("enrollment failure enabled or started")
		}
	}
	if _, e := c.fs.observe(p, "enable-link", p.UnitName); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("enable link created before verification")
	}
	got, e := c.uninstall(context.Background())
	if e != nil || !got.Complete {
		t.Fatal("empty uninstall", e)
	}
	if runtime.logoutCalls != 0 {
		t.Fatal("empty state invented a Vault/logout")
	}
	if _, e = c.lease.LoadReceipt(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("receipt not removed")
	}
	runtime.drainErr = ErrBusy
	if _, e = c.uninstall(context.Background()); !errors.Is(e, ErrBusy) {
		t.Fatal("already absent ignored live cgroup", e)
	}
	runtime.drainErr = nil
	if _, e = c.uninstall(context.Background()); e != nil {
		t.Fatal("completed retry failed", e)
	}
}
func TestLinuxCoordinatorRecoversExactPublishedCreationAndNeverTwoLinks(t *testing.T) {
	c, p, _ := nativeFixture(t)
	r := currentReceipt(t)
	r.Plan = p
	u, _ := p.Unit()
	h := sha256.Sum256(u.Content)
	r.UnitSHA256 = hex.EncodeToString(h[:])
	r.Creations = creationPlan(p)
	if e := c.lease.CreateReceipt(r); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 2; n++ {
		next := copyReceipt(r)
		next.Creations[n].Intent = true
		if e := c.saveReceipt(&r, next); e != nil {
			t.Fatal(e)
		}
		if e := c.fs.create(p, r.Creations[n], r); e != nil {
			t.Fatal(e)
		}
		if n == 0 {
			i, e := c.fs.verifyCreation(r, r.Creations[n])
			if e != nil {
				t.Fatal(e)
			}
			next = copyReceipt(r)
			next.Creations[n].Observed = &i
			if e = c.saveReceipt(&r, next); e != nil {
				t.Fatal(e)
			}
		}
	}
	// The binary was published but its observed receipt commit was interrupted.
	if _, e := c.install(context.Background(), p); e != nil {
		t.Fatal("published creation did not converge", e)
	}
	for _, name := range []string{p.Input.UID + ".installation.json"} {
		var st unix.Stat_t
		if unix.Fstatat(c.lease.store.dir, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Nlink != 1 {
			t.Fatal("metadata publication retained a hardlink")
		}
	}
	if _, e := c.uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestLinuxCoordinatorBusyAndFreshAccountAfterLogoutPreserveEverything(t *testing.T) {
	c, p, runtime := nativeFixture(t)
	installFixture(t, c, p)
	writeUserFixture(t, c, p, "vault.lock")
	fd, e := unix.Open(c.fs.path(filepath.Join(p.StateDirectory, "vault.lock")), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		t.Fatal("fixture lock")
	}
	if _, e = c.uninstall(context.Background()); !errors.Is(e, ErrBusy) {
		t.Fatal("owner not rejected", e)
	}
	if runtime.logoutCalls != 0 {
		t.Fatal("busy owner was logged out")
	}
	unix.Flock(fd, unix.LOCK_UN)
	unix.Close(fd)
	runtime.logoutHook = func(p Plan) error { writeUserFixture(t, c, p, "trust.v1.enc"); return nil }
	if _, e = c.uninstall(context.Background()); !errors.Is(e, ErrConflict) {
		t.Fatal("new account was deleted after completion receipt", e)
	}
	if _, e = os.Stat(c.fs.path(filepath.Join(p.StateDirectory, "trust.v1.enc"))); e != nil {
		t.Fatal("new account material lost")
	}
	j, e := c.lease.LoadJournal()
	if e != nil || j.Phase != "service-drained" || len(j.Deletions) != 0 {
		t.Fatal("cleanup was authorized despite fresh account")
	}
}
func TestLinuxCoordinatorResumesOnlyExactPersistedDeletionIntent(t *testing.T) {
	c, p, _ := nativeFixture(t)
	r := installFixture(t, c, p)
	snap := copyReceipt(r)
	j := Journal{Schema: JournalSchema, InstallationID: r.InstallationID, Plan: p, Phase: "uninstall-requested", Revision: 1, Receipt: &snap}
	if e := c.lease.CreateJournal(j); e != nil {
		t.Fatal(e)
	}
	if e := c.lease.CreateUninstallGuard(); e != nil {
		t.Fatal(e)
	}
	if e := c.advance(&j, "service-drained"); e != nil {
		t.Fatal(e)
	}
	freeze, e := c.freezeState(r)
	if e != nil {
		t.Fatal(e)
	}
	objects, e := c.cleanupObjects(r, freeze)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.advance(&j, "offline-closed"); e != nil {
		t.Fatal(e)
	}
	next := copyJournalRecord(j)
	next.Phase = "cleanup-authorized"
	for _, i := range objects {
		next.Deletions = append(next.Deletions, Deletion{Object: i})
	}
	if e = c.saveJournal(&j, next); e != nil {
		t.Fatal(e)
	}
	if e = freeze.closeFrozen(); e != nil {
		t.Fatal(e)
	}
	n := 0
	for j.Deletions[n].Object.Area != "state-directory" {
		n++
	}
	next = copyJournalRecord(j)
	next.Deletions[n].Intent = true
	if e = c.saveJournal(&j, next); e != nil {
		t.Fatal(e)
	}
	if e = c.fs.remove(p, j.Deletions[n].Object); e != nil {
		t.Fatal(e)
	}
	// Crash after unlink/fsync, before 'removed' commit: resume original intent.
	if _, e = c.uninstall(context.Background()); e != nil {
		t.Fatal("authorized unlink restart", e)
	}
	if _, e = os.Stat(c.fs.path(p.ProgramDirectory)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("program remained")
	}
}

func TestLinuxFrozenIPCBindingRejectsReplacedNamespace(t *testing.T) {
	c, p, _ := nativeFixture(t)
	installFixture(t, c, p)
	state, e := openDirectory(c.fs.path(p.StateDirectory))
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(state)
	uid, _ := parseUID(p.Input.UID)
	gid, _ := parseUID(p.Input.GID)
	path := c.fs.path(filepath.Join(p.StateDirectory, "ipc"))
	if os.Mkdir(path, 0700) != nil || os.Chown(path, int(uid), int(gid)) != nil {
		t.Fatal("synthetic IPC")
	}
	i, e := observeAt(state, "ipc", "ipc-directory")
	if e != nil {
		t.Fatal(e)
	}
	ipc, e := unix.Openat(state, "ipc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(ipc)
	if !fdMatchesIdentity(ipc, i) {
		t.Fatal("original fd mismatch")
	}
	if os.Rename(path, path+"-moved") != nil || os.Mkdir(path, 0700) != nil || os.Chown(path, int(uid), int(gid)) != nil {
		t.Fatal("fixture namespace switch")
	}
	f := &frozenState{fs: c.fs, p: p, state: state, ipc: ipc}
	if e = f.checkBindings(); e != ErrConflict {
		t.Fatal("held IPC fd mistaken for new namespace", e)
	}
}
