//go:build linux

package linuxinstall

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/user"
	"time"
)

type Result struct {
	Version  int    `json:"version"`
	UID      string `json:"uid"`
	Phase    string `json:"phase"`
	Complete bool   `json:"complete"`
}
type coordinator struct {
	lease   *AdminLease
	fs      layout
	runtime runtimeActions
}

// Install stages a disabled unit. Real user enrollment and Start remain explicit.
func Install(ctx context.Context, in Input) (Result, error) {
	p, e := NewPlan(in)
	if e != nil {
		return Result{}, e
	}
	if e = checkUser(p); e != nil {
		return Result{}, e
	}
	if rootIdentity() != nil {
		return Result{}, ErrPermission
	}
	fs := layout{}
	if e = fs.prepare(); e != nil {
		return Result{}, e
	}
	return withCoordinator(ctx, in.UID, func(c *coordinator) (Result, error) { return c.install(ctx, p) })
}
func Start(ctx context.Context, uid string) (Result, error) {
	return withCoordinator(ctx, uid, func(c *coordinator) (Result, error) { return c.start(ctx) })
}
func Uninstall(ctx context.Context, uid string) (Result, error) {
	return withCoordinator(ctx, uid, func(c *coordinator) (Result, error) { return c.uninstall(ctx) })
}
func withCoordinator(ctx context.Context, uid string, fn func(*coordinator) (Result, error)) (Result, error) {
	if !decimalID(uid, true) || rootIdentity() != nil {
		return Result{}, ErrPermission
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	s, e := OpenAdminStore()
	if e != nil {
		return Result{}, e
	}
	l, e := s.Acquire(uid)
	if e != nil {
		return Result{}, errors.Join(e, s.Close())
	}
	c := &coordinator{lease: l, fs: layout{}, runtime: nativeActions{lease: l}}
	r, e := fn(c)
	closeErr := errors.Join(l.Close(), s.Close())
	if e != nil || closeErr != nil {
		return Result{}, errors.Join(e, closeErr)
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	return r, nil
}
func checkUser(p Plan) error {
	u, e := user.Lookup(p.Input.UserName)
	if e != nil || u.Uid != p.Input.UID || u.Gid != p.Input.GID {
		return ErrConflict
	}
	return nil
}
func (c *coordinator) absentMetadata(name string) error {
	_, e := c.lease.read(c.lease.uid + name)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	return ErrConflict
}
func (c *coordinator) saveReceipt(r *Receipt, next Receipt) error {
	next.Revision = r.Revision + 1
	if e := c.lease.CommitReceipt(r.Revision, next); e != nil {
		return e
	}
	*r = next
	return nil
}
func (c *coordinator) saveJournal(j *Journal, next Journal) error {
	next.Revision = j.Revision + 1
	if e := c.lease.CommitJournal(j.Revision, next); e != nil {
		return e
	}
	*j = next
	return nil
}
func (c *coordinator) advance(j *Journal, phase string) error {
	n := copyJournalRecord(*j)
	n.Phase = phase
	return c.saveJournal(j, n)
}

// Only install/start require this execution readiness capability. Uninstall
// must remain available for an old manager or a rejected exec installation.
func (c *coordinator) checkUnitType(ctx context.Context, r Receipt) error {
	expected, err := r.executionType()
	if err != nil {
		return err
	}
	return c.runtime.unitType(ctx, r.Plan, expected)
}

func (c *coordinator) install(ctx context.Context, p Plan) (Result, error) {
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	if e := c.absentMetadata(".uninstall.json"); e != nil {
		return Result{}, e
	}
	if e := c.absentMetadata(".uninstalling"); e != nil {
		return Result{}, e
	}
	r, e := c.lease.LoadReceipt()
	if errors.Is(e, os.ErrNotExist) {
		s, showErr := c.runtime.show(ctx, p)
		if showErr != nil {
			return Result{}, showErr
		}
		if s.LoadState != "not-found" || !s.NormalStop() {
			return Result{}, ErrConflict
		}
		source, sourceErr := checkedBinarySource(p.Input.BinarySource, p.Input.BinarySHA256)
		if sourceErr != nil {
			return Result{}, sourceErr
		}
		if source.Close() != nil {
			return Result{}, ErrPersistence
		}
		if p.CAPath != "" {
			source, sourceErr = checkedCASource(p.Input.CASource, p.Input.CASHA256)
			if sourceErr != nil {
				return Result{}, sourceErr
			}
			if source.Close() != nil {
				return Result{}, ErrPersistence
			}
		}
		if e = c.fs.checkSystemdNamespace(p, false, false); e != nil {
			return Result{}, e
		}
		for _, o := range creationPlan(p) {
			_, e = c.fs.observe(p, o.Area, o.Name)
			if !errors.Is(e, os.ErrNotExist) {
				if e == nil {
					e = ErrConflict
				}
				return Result{}, e
			}
		}
		u, _ := p.Unit()
		h := sha256.Sum256(u.Content)
		var id [16]byte
		if _, e = io.ReadFull(rand.Reader, id[:]); e != nil {
			return Result{}, ErrPersistence
		}
		r = Receipt{Schema: ReceiptSchema, InstallationID: hex.EncodeToString(id[:]), Plan: p, UnitSHA256: hex.EncodeToString(h[:]), Phase: "install-planned", Revision: 1, Creations: creationPlan(p)}
		if e = c.lease.CreateReceipt(r); e != nil {
			return Result{}, e
		}
	} else if e != nil {
		return Result{}, e
	}
	if r.Plan != p || r.Revision == 0 {
		return Result{}, ErrConflict
	}
	if r.Phase != "install-planned" {
		if e = c.fs.verifyReceipt(r); e != nil {
			return Result{}, e
		}
		if e = c.checkUnitType(ctx, r); e != nil {
			return Result{}, e
		}
		return Result{1, p.Input.UID, r.Phase, true}, nil
	}
	if e = c.fs.checkSystemdNamespace(p, creationIntended(r, "unit"), false); e != nil {
		return Result{}, e
	}
	for n := range r.Creations {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		o := r.Creations[n]
		if !o.Intent {
			if _, e = c.fs.observe(p, o.Area, o.Name); !errors.Is(e, os.ErrNotExist) {
				if e == nil {
					e = ErrConflict
				}
				return Result{}, e
			}
			next := copyReceipt(r)
			next.Creations[n].Intent = true
			if e = c.saveReceipt(&r, next); e != nil {
				return Result{}, e
			}
			o = r.Creations[n]
		}
		i, e := c.fs.verifyCreation(r, o)
		if errors.Is(e, os.ErrNotExist) && o.Observed == nil {
			if e = c.fs.create(p, o, r); e != nil {
				return Result{}, e
			}
			i, e = c.fs.verifyCreation(r, o)
		}
		if e != nil {
			return Result{}, e
		}
		if o.Observed == nil {
			next := copyReceipt(r)
			next.Creations[n].Observed = &i
			if e = c.saveReceipt(&r, next); e != nil {
				return Result{}, e
			}
		}
	}
	if !r.HandoffIntent {
		next := copyReceipt(r)
		next.HandoffIntent = true
		if e = c.saveReceipt(&r, next); e != nil {
			return Result{}, e
		}
	}
	if e = c.handoff(r); e != nil {
		return Result{}, e
	}
	if e = c.runtime.control(ctx, "daemon-reload", p); e != nil {
		return Result{}, e
	}
	if e = c.checkUnitType(ctx, r); e != nil {
		return Result{}, e
	}
	s, e := c.runtime.show(ctx, p)
	if e != nil {
		return Result{}, e
	}
	if !s.NormalStop() || s.UnitFileState != "disabled" {
		return Result{}, ErrConflict
	}
	next := copyReceipt(r)
	next.Phase = "installed-disabled"
	if e = c.saveReceipt(&r, next); e != nil {
		return Result{}, e
	}
	return Result{1, p.Input.UID, r.Phase, true}, nil
}
func creationIntended(r Receipt, area string) bool {
	for _, c := range r.Creations {
		if c.Area == area && c.Intent {
			return true
		}
	}
	return false
}
func creationObserved(r Receipt, area string) bool {
	for _, c := range r.Creations {
		if c.Area == area && c.Observed != nil {
			return true
		}
	}
	return false
}
func (c *coordinator) handoff(r Receipt) error {
	for _, o := range r.Creations {
		if _, e := c.fs.verifyCreation(r, o); e != nil {
			return e
		}
	}
	fd, e := openDirectory(c.fs.path(r.Plan.ProgramDirectory))
	if e != nil {
		return e
	}
	if unix.Fchmod(fd, 0755) != nil || unix.Fsync(fd) != nil {
		unix.Close(fd)
		return ErrPersistence
	}
	if unix.Close(fd) != nil {
		return ErrPersistence
	}
	fd, e = openDirectory(c.fs.path(r.Plan.StateDirectory))
	if e != nil {
		return e
	}
	uid, _ := parseUID(r.Plan.Input.UID)
	gid, _ := parseUID(r.Plan.Input.GID)
	if unix.Fchown(fd, int(uid), int(gid)) != nil || unix.Fchmod(fd, 0700) != nil || unix.Fsync(fd) != nil {
		unix.Close(fd)
		return ErrPersistence
	}
	if unix.Close(fd) != nil {
		return ErrPersistence
	}
	return nil
}
func (c *coordinator) start(ctx context.Context) (Result, error) {
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if e := c.absentMetadata(".uninstall.json"); e != nil {
		return Result{}, e
	}
	if e := c.absentMetadata(".uninstalling"); e != nil {
		return Result{}, e
	}
	r, e := c.lease.LoadReceipt()
	if e != nil {
		return Result{}, e
	}
	p := r.Plan
	if r.Phase == "install-planned" || checkUser(p) != nil {
		return Result{}, ErrState
	}
	if e = c.fs.verifyReceipt(r); e != nil {
		return Result{}, e
	}
	if e = c.checkUnitType(ctx, r); e != nil {
		return Result{}, e
	}
	s, e := c.runtime.show(ctx, p)
	if e != nil {
		return Result{}, e
	}
	if s.ActiveState == "active" {
		if !r.EnableIntent || s.UnitFileState != "enabled" {
			return Result{}, ErrConflict
		}
		i, e := c.fs.observe(p, "enable-link", p.UnitName)
		if e != nil || i.validate(p) != nil {
			return Result{}, ErrConflict
		}
		if r.EnableIdentity == nil {
			next := copyReceipt(r)
			next.EnableIdentity = &i
			if e = c.saveReceipt(&r, next); e != nil {
				return Result{}, e
			}
		} else if i != *r.EnableIdentity {
			return Result{}, ErrConflict
		}
		if r.Phase != "enabled" {
			next := copyReceipt(r)
			next.Phase = "enabled"
			if e = c.saveReceipt(&r, next); e != nil {
				return Result{}, e
			}
		}
		return Result{1, p.Input.UID, "enabled", true}, nil
	}
	if !s.NormalStop() {
		return Result{}, ErrState
	}
	if e = c.runtime.drained(ctx, p); e != nil {
		return Result{}, e
	}
	if e = c.runtime.enrollment(ctx, p); e != nil {
		return Result{}, e
	}
	if !r.EnableIntent {
		next := copyReceipt(r)
		next.EnableIntent = true
		if e = c.saveReceipt(&r, next); e != nil {
			return Result{}, e
		}
	}
	if e = c.fs.checkSystemdNamespace(p, true, true); e != nil {
		return Result{}, e
	}
	if e = c.runtime.control(ctx, "enable", p); e != nil {
		return Result{}, e
	}
	i, e := c.fs.observe(p, "enable-link", p.UnitName)
	if e != nil || i.validate(p) != nil {
		return Result{}, ErrConflict
	}
	if r.EnableIdentity == nil {
		next := copyReceipt(r)
		next.EnableIdentity = &i
		if e = c.saveReceipt(&r, next); e != nil {
			return Result{}, e
		}
	} else if i != *r.EnableIdentity {
		return Result{}, ErrConflict
	}
	// enable implicitly reloads the manager: bind the final readiness check to
	// the configuration that will be started, while preserving the early gate.
	if e = c.fs.verifyReceipt(r); e != nil {
		return Result{}, e
	}
	if e = c.checkUnitType(ctx, r); e != nil {
		return Result{}, e
	}
	s, e = c.runtime.show(ctx, p)
	if e != nil {
		return Result{}, e
	}
	if !s.NormalStop() || s.UnitFileState != "enabled" {
		return Result{}, ErrConflict
	}
	if e = c.runtime.control(ctx, "start", p); e != nil {
		return Result{}, e
	}
	s, e = c.runtime.show(ctx, p)
	if e != nil {
		return Result{}, e
	}
	if s.ActiveState != "active" || s.UnitFileState != "enabled" || s.MainPID == 0 {
		return Result{}, ErrState
	}
	if e = c.fs.verifyReceipt(r); e != nil {
		return Result{}, e
	}
	if r.Phase != "enabled" {
		next := copyReceipt(r)
		next.Phase = "enabled"
		if e = c.saveReceipt(&r, next); e != nil {
			return Result{}, e
		}
	}
	return Result{1, p.Input.UID, "enabled", true}, nil
}
func (c *coordinator) uninstall(ctx context.Context) (result Result, resultErr error) {
	var held *frozenState
	defer func() {
		if held != nil {
			if e := held.closeFrozen(); e != nil {
				result = Result{}
				resultErr = errors.Join(resultErr, e)
			}
		}
	}()
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	j, je := c.lease.LoadJournal()
	r, re := c.lease.LoadReceipt()
	if je != nil && !errors.Is(je, os.ErrNotExist) {
		return Result{}, je
	}
	if re != nil && !errors.Is(re, os.ErrNotExist) {
		return Result{}, re
	}
	if errors.Is(je, os.ErrNotExist) {
		if re != nil {
			if errors.Is(re, os.ErrNotExist) {
				return c.verifyAlreadyAbsent(ctx)
			}
			return Result{}, re
		}
		if r.Revision == 0 {
			return Result{}, ErrUnsupported
		}
		// A known creation intent may have published an object before receipt fsync.
		for n, o := range r.Creations {
			i, e := c.fs.verifyCreation(r, o)
			if errors.Is(e, os.ErrNotExist) && o.Observed == nil {
				continue
			}
			if e != nil {
				return Result{}, e
			}
			if o.Observed == nil {
				if !o.Intent {
					return Result{}, ErrConflict
				}
				next := copyReceipt(r)
				next.Creations[n].Observed = &i
				if e = c.saveReceipt(&r, next); e != nil {
					return Result{}, e
				}
			}
		}
		if r.EnableIntent && r.EnableIdentity == nil {
			i, e := c.fs.observe(r.Plan, "enable-link", r.Plan.UnitName)
			if e == nil {
				if i.validate(r.Plan) != nil {
					return Result{}, ErrConflict
				}
				next := copyReceipt(r)
				next.EnableIdentity = &i
				if e = c.saveReceipt(&r, next); e != nil {
					return Result{}, e
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				return Result{}, e
			}
		}
		snap := copyReceipt(r)
		j = Journal{Schema: JournalSchema, InstallationID: r.InstallationID, Plan: r.Plan, Phase: "uninstall-requested", Revision: 1, Receipt: &snap}
		if e := c.lease.CreateJournal(j); e != nil {
			return Result{}, e
		}
	} else {
		if j.Receipt == nil {
			return Result{}, ErrUnsupported
		}
		if re == nil {
			a, _ := json.Marshal(r)
			b, _ := json.Marshal(*j.Receipt)
			if string(a) != string(b) {
				return Result{}, ErrConflict
			}
		} else if j.Phase != "completed" {
			return Result{}, ErrState
		}
		r = *j.Receipt
	}
	p := j.Plan
	if j.Phase == "completed" {
		return c.finish(ctx, &j)
	}
	if checkUser(p) != nil {
		return Result{}, ErrConflict
	}
	if j.Phase != "uninstall-requested" {
		if e := c.verifyUninstallGuard(j); e != nil {
			return Result{}, e
		}
	}
	if j.Phase == "uninstall-requested" {
		if e := c.lease.CreateUninstallGuard(); e != nil {
			return Result{}, e
		}
		if e := c.fs.checkSystemdNamespace(p, creationObserved(r, "unit"), r.EnableIdentity != nil); e != nil {
			return Result{}, e
		}
		s, e := c.runtime.show(ctx, p)
		if e != nil {
			return Result{}, e
		}
		if s.ActiveState == "active" {
			if e = c.runtime.control(ctx, "stop", p); e != nil {
				return Result{}, e
			}
		}
		if e = c.runtime.drained(ctx, p); e != nil {
			return Result{}, e
		}
		if e = c.advance(&j, "service-drained"); e != nil {
			return Result{}, e
		}
	}
	if j.Phase == "service-drained" || j.Phase == "offline-closed" {
		if e := c.runtime.drained(ctx, p); e != nil {
			return Result{}, e
		}
		freeze, e := c.freezeState(r)
		if e != nil {
			return Result{}, e
		}
		if !freeze.empty {
			if e = freeze.restoreAndClose(); e != nil {
				return Result{}, e
			}
			if e = c.runtime.logout(ctx, p); e != nil {
				return Result{}, e
			}
			freeze, e = c.freezeState(r)
			if e != nil {
				return Result{}, e
			}
		}
		// All account slots must be physically absent under the final frozen locks.
		objects, e := c.cleanupObjects(r, freeze)
		if e != nil {
			return Result{}, errors.Join(e, freeze.restoreAndClose())
		}
		if j.Phase == "service-drained" {
			if e = c.advance(&j, "offline-closed"); e != nil {
				return Result{}, errors.Join(e, freeze.restoreAndClose())
			}
		}
		next := copyJournalRecord(j)
		next.Phase = "cleanup-authorized"
		for _, i := range objects {
			next.Deletions = append(next.Deletions, Deletion{Object: i})
		}
		if e = c.saveJournal(&j, next); e != nil {
			return Result{}, errors.Join(e, freeze.restoreAndClose())
		}
		held = freeze
	}
	if held == nil && journalPhases[j.Phase] >= 3 {
		var e error
		held, e = c.lockAuthorizedState(j)
		if e != nil {
			return Result{}, e
		}
	}
	for _, phase := range []struct {
		before, after string
		areas         map[string]bool
	}{{"cleanup-authorized", "files-removed", map[string]bool{"state": true, "ipc": true, "ipc-directory": true, "state-directory": true}}, {"files-removed", "unit-removed", map[string]bool{"enable-link": true, "unit": true}}, {"unit-removed", "program-removed", map[string]bool{"program": true, "program-directory": true}}} {
		if j.Phase != phase.before {
			continue
		}
		if e := c.runtime.drained(ctx, p); e != nil {
			return Result{}, e
		}
		if e := c.deleteAreas(ctx, &j, phase.areas); e != nil {
			return Result{}, e
		}
		if phase.after == "unit-removed" {
			if e := c.runtime.control(ctx, "daemon-reload", p); e != nil {
				return Result{}, e
			}
			s, e := c.runtime.show(ctx, p)
			if e != nil {
				return Result{}, e
			}
			if s.LoadState != "not-found" {
				return Result{}, ErrConflict
			}
		}
		if e := c.advance(&j, phase.after); e != nil {
			return Result{}, e
		}
	}
	if j.Phase == "program-removed" {
		if e := c.advance(&j, "completed"); e != nil {
			return Result{}, e
		}
	}
	return c.finish(ctx, &j)
}
func (c *coordinator) finish(ctx context.Context, j *Journal) (Result, error) {
	if j.Phase != "completed" || j.Validate() != nil {
		return Result{}, ErrState
	}
	for _, d := range j.Deletions {
		_, e := c.fs.observe(j.Plan, d.Object.Area, d.Object.Name)
		if !errors.Is(e, os.ErrNotExist) {
			if e == nil {
				e = ErrConflict
			}
			return Result{}, e
		}
	}
	if e := c.fs.checkSystemdNamespace(j.Plan, false, false); e != nil {
		return Result{}, e
	}
	s, e := c.runtime.show(ctx, j.Plan)
	if e != nil || s.LoadState != "not-found" {
		return Result{}, ErrConflict
	}
	if e = c.runtime.drained(ctx, j.Plan); e != nil {
		return Result{}, e
	}
	for _, suffix := range []string{".uninstalling", ".installation.json", ".uninstall.json"} {
		name := c.lease.uid + suffix
		b, e := c.lease.read(name)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return Result{}, e
		}
		if suffix == ".uninstalling" && string(b) != j.InstallationID+"\n" {
			return Result{}, ErrConflict
		}
		if suffix == ".installation.json" {
			r, e := DecodeReceipt(b)
			if e != nil || r.InstallationID != j.InstallationID {
				return Result{}, ErrConflict
			}
		}
		if suffix == ".uninstall.json" {
			r, e := DecodeJournal(b)
			if e != nil || r.InstallationID != j.InstallationID || r.Phase != "completed" {
				return Result{}, ErrConflict
			}
		}
		if c.lease.guard() != nil || unix.Unlinkat(c.lease.store.dir, name, 0) != nil || unix.Fsync(c.lease.store.dir) != nil {
			return Result{}, ErrPersistence
		}
	}
	return Result{1, j.Plan.Input.UID, "completed", true}, nil
}
func (c *coordinator) deleteAreas(ctx context.Context, j *Journal, areas map[string]bool) error {
	for n, d := range j.Deletions {
		if !areas[d.Object.Area] || d.Removed {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !d.Intent {
			next := copyJournalRecord(*j)
			next.Deletions[n].Intent = true
			if e := c.saveJournal(j, next); e != nil {
				return e
			}
			d = j.Deletions[n]
		}
		i, e := c.fs.observe(j.Plan, d.Object.Area, d.Object.Name)
		if errors.Is(e, os.ErrNotExist) {
			if !MissingObjectAllowed(*j, n) {
				return ErrState
			}
			if e = c.fs.syncAbsentParent(j.Plan, d.Object); e != nil {
				return e
			}
		} else {
			if e != nil {
				return e
			}
			if !deletionIdentityMatches(i, d.Object) {
				return ErrConflict
			}
			if e = c.fs.remove(j.Plan, i); e != nil {
				return e
			}
		}
		next := copyJournalRecord(*j)
		next.Deletions[n].Removed = true
		if e = c.saveJournal(j, next); e != nil {
			return e
		}
	}
	return nil
}

// The command bounds the whole coordinator; individual stop has a shorter deadline.
func CommandTimeout() time.Duration { return 90 * time.Second }

func (c *coordinator) verifyAlreadyAbsent(ctx context.Context) (Result, error) {
	if e := c.absentMetadata(".uninstalling"); e != nil {
		return Result{}, e
	}
	u, e := user.LookupId(c.lease.uid)
	if e != nil {
		return Result{}, ErrPlan
	}
	p, e := NewPlan(Input{UserName: u.Username, UID: u.Uid, GID: u.Gid, BinarySource: "/nonexistent", BinarySHA256: "0000000000000000000000000000000000000000000000000000000000000000"})
	if e != nil {
		return Result{}, e
	}
	for _, o := range creationPlan(p) {
		_, e = c.fs.observe(p, o.Area, o.Name)
		if !errors.Is(e, os.ErrNotExist) {
			return Result{}, ErrConflict
		}
	}
	if e = c.fs.checkSystemdNamespace(p, false, false); e != nil {
		return Result{}, e
	}
	s, e := c.runtime.show(ctx, p)
	if e != nil || s.LoadState != "not-found" {
		return Result{}, ErrConflict
	}
	if e = c.runtime.drained(ctx, p); e != nil {
		return Result{}, e
	}
	return Result{1, p.Input.UID, "completed", true}, nil
}

func (c *coordinator) verifyUninstallGuard(j Journal) error {
	b, e := c.lease.read(c.lease.uid + ".uninstalling")
	if e != nil {
		return e
	}
	if string(b) != j.InstallationID+"\n" {
		return ErrConflict
	}
	return nil
}
