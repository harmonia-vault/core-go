package macosservice

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
)

type absenceFS interface {
	durableAbsence(string) error
}

type localRunner interface {
	offlineLogout(context.Context, layout, Target) error
	enrollmentCheck(context.Context, layout, Target) error
}

func accountFile(name string) bool {
	switch name {
	case "device.v1.enc", "session.v1.enc", "trust.v1.enc", "writes.v1.enc", "recovery.dag.v1.enc":
		return true
	}
	return false
}
func cleanupOrder(xs []item) []item {
	result := append([]item{}, xs...)
	rank := func(x item) int {
		switch x.Scope {
		case "ipc":
			if x.Name == "" {
				return 3
			}
			if x.Name == "ipc.lock" {
				return 2
			}
			return 1
		case "state":
			if x.Name == "" {
				return 6
			}
			if x.Name == "vault.lock" {
				return 5
			}
			return 4
		case "plist":
			return 7
		case "program":
			switch x.Name {
			case "ca.pem":
				return 8
			case "harmonia":
				return 9
			case "installation.json":
				return 10
			case "":
				return 11
			}
		}
		return 100
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := rank(result[i]), rank(result[j])
		if a == b {
			return result[i].Name < result[j].Name
		}
		return a < b
	})
	return result
}
func (m *Manager) checkedItem(scope, name string, n node) (item, error) {
	x := item{Scope: scope, Name: name, Node: n}
	if n.Kind == regular {
		p, e := m.itemPath(x)
		if e != nil {
			return x, e
		}
		b, e := m.fs.read(p, n, 128<<20)
		if e != nil {
			return x, e
		}
		x.Hash = digest(b)
		clear(b)
	}
	return x, nil
}
func (m *Manager) prepareJournal(r receipt) (journal, error) {
	l := paths(m.target)
	j := journal{Version: 1, Installation: r, Phase: "preparing"}
	for _, d := range []struct{ scope, path string }{{"program", l.Program}, {"state", l.State}} {
		uid, mode := uint32(0), uint32(0755)
		if d.scope == "state" {
			uid = m.target.UID
			mode = 0700
		}
		n, e := m.checkedDir(d.path, uid, mode)
		if e != nil {
			return j, e
		}
		j.Directories = append(j.Directories, item{Scope: d.scope, Node: n})
	}
	if n, e := m.fs.inspect(l.State + "/ipc"); e == nil {
		if n.Kind != directory || n.UID != m.target.UID || n.GID != m.target.GID || n.Mode != 0700 || n.ACL {
			return j, ErrUnknown
		}
		j.Directories = append(j.Directories, item{Scope: "ipc", Node: n})
	} else if !errors.Is(e, os.ErrNotExist) {
		return j, e
	}
	for _, f := range []struct{ scope, name, path string }{{"program", "harmonia", l.Binary}, {"program", "installation.json", l.Receipt}, {"plist", "", l.Plist}} {
		n, e := m.fs.inspect(f.path)
		if e != nil {
			return j, e
		}
		x, e := m.checkedItem(f.scope, f.name, n)
		if e != nil {
			return j, e
		}
		j.RootFiles = append(j.RootFiles, x)
	}
	if r.CASHA256 != "" {
		n, e := m.fs.inspect(l.CA)
		if e != nil {
			return j, e
		}
		x, e := m.checkedItem("program", "ca.pem", n)
		if e != nil {
			return j, e
		}
		j.RootFiles = append(j.RootFiles, x)
	}
	return j, m.validJournal(j)
}
func (m *Manager) ensureAbsent(ctx context.Context, l layout) error {
	s, e := m.runner.state(ctx, l, m.target)
	if e != nil {
		return e
	}
	if s != absent {
		return ErrUnknown
	}
	return nil
}
func (m *Manager) stopForUninstall(ctx context.Context, l layout) error {
	r, ok := m.runner.(launchRunner)
	if !ok {
		return ErrUnknown
	}
	s, e := r.observeJob(ctx, l, m.target)
	if e != nil {
		return e
	}
	if s.State == absent {
		return nil
	}
	if s.State != matching {
		return ErrUnknown
	}
	if s.PID < 2 {
		if !s.StableNoPID {
			return ErrUnknown
		}
		return m.stopOwned(ctx, l, true)
	}
	if e = m.runner.logout(ctx, l, m.target); e != nil {
		return e
	}
	return m.stopOwned(ctx, l, false)
}

type frozenScope struct {
	m     *Manager
	dirs  []item
	locks []io.Closer
}

func (g *frozenScope) close(restore bool) error {
	var e error
	for i := len(g.locks) - 1; i >= 0; i-- {
		e = errors.Join(e, g.locks[i].Close())
	}
	g.locks = nil
	if restore {
		for i := len(g.dirs) - 1; i >= 0; i-- {
			x := g.dirs[i]
			p, _ := g.m.itemPath(x)
			_, v := g.m.fs.owner(p, x.Node, g.m.target.UID, g.m.target.GID)
			e = errors.Join(e, v)
		}
	}
	g.dirs = nil
	return e
}

// account scope 的目录所有权只按已持久记录的 inode 改变；未知对象保留。
func (m *Manager) freeze(j journal) (g *frozenScope, xs []item, err error) {
	g = &frozenScope{m: m}
	defer func() {
		if err != nil {
			err = errors.Join(err, g.close(true))
		}
	}()
	for _, scope := range []string{"ipc", "state"} {
		for _, d := range j.Directories {
			if d.Scope != scope {
				continue
			}
			p, _ := m.itemPath(d)
			n, e := m.fs.inspect(p)
			if e != nil {
				return g, nil, e
			}
			if !n.same(d.Node) || n.ACL || n.Mode != 0700 || !((n.UID == m.target.UID && n.GID == m.target.GID) || (n.UID == 0 && n.GID == 0)) {
				return g, nil, ErrUnknown
			}
			if n.UID != 0 {
				n, e = m.fs.owner(p, n, 0, 0)
				if e != nil {
					return g, nil, e
				}
			}
			g.dirs = append(g.dirs, item{Scope: scope, Node: n})
		}
	}
	xs, err = m.collectState(j)
	if err != nil {
		return g, nil, err
	}
	if len(xs) == 1 && len(g.dirs) == 1 {
		return g, xs, nil
	} // state 严格为空，没有 IPC 或材料。
	for _, want := range []item{{Scope: "state", Name: "vault.lock"}, {Scope: "ipc", Name: "ipc.lock"}} {
		if want.Scope == "ipc" && len(g.dirs) == 1 {
			continue
		}
		found := false
		for _, x := range xs {
			if x.Scope == want.Scope && x.Name == want.Name {
				p, _ := m.itemPath(x)
				h, e := m.fs.claimLock(p, x.Node)
				if e != nil {
					return g, nil, e
				}
				g.locks = append(g.locks, h)
				found = true
			}
		}
		if !found {
			return g, nil, ErrUnknown
		}
	}
	// 获锁之后重新核所有条目/摘要，不能以第一次枚举替代锁下检查。
	checked, e := m.collectState(j)
	if e != nil {
		return g, nil, e
	}
	if !sameItems(xs, checked) {
		return g, nil, ErrUnknown
	}
	return g, xs, nil
}
func sameItems(a, b []item) bool {
	a = cleanupOrder(a)
	b = cleanupOrder(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (m *Manager) collectState(j journal) ([]item, error) {
	var result []item
	l := paths(m.target)
	dirs := map[string]node{}
	for _, d := range j.Directories {
		dirs[d.Scope] = d.Node
	}
	for _, scope := range []string{"state", "ipc"} {
		original, ok := dirs[scope]
		if !ok {
			continue
		}
		dir := item{Scope: scope}
		p, _ := m.itemPath(dir)
		n, e := m.fs.inspect(p)
		if e != nil {
			return nil, e
		}
		if !original.same(n) || n.Kind != directory || n.UID != 0 || n.GID != 0 || n.Mode != 0700 || n.ACL {
			return nil, ErrUnknown
		}
		dir.Node = n
		result = append(result, dir)
		xs, e := m.fs.children(p)
		if e != nil {
			return nil, e
		}
		for _, entry := range xs {
			if scope == "state" && entry.Name == "ipc" {
				expected, ok := dirs["ipc"]
				if !ok || !expected.same(entry.Node) {
					return nil, ErrUnknown
				}
				continue
			}
			valid := scope == "state" && stateFiles[entry.Name] || scope == "ipc" && (entry.Name == "ipc.lock" || entry.Name == "harmonia.sock")
			n := entry.Node
			if !valid || n.UID != m.target.UID || n.Mode != 0600 || n.ACL || (n.Kind != regular && !(scope == "ipc" && entry.Name == "harmonia.sock" && n.Kind == socket)) || n.Kind == regular && n.Links != 1 {
				return nil, ErrUnknown
			}
			x, e := m.checkedItem(scope, entry.Name, n)
			if e != nil {
				return nil, e
			}
			result = append(result, x)
		}
	}
	if _, ok := dirs["ipc"]; !ok {
		if _, e := m.fs.inspect(l.State + "/ipc"); !errors.Is(e, os.ErrNotExist) {
			return nil, ErrUnknown
		}
	}
	return cleanupOrder(result), nil
}
func (m *Manager) checkRoot(j journal) error {
	r, e := m.verifyRoot()
	if e != nil || r != j.Installation {
		return ErrUnknown
	}
	for _, x := range j.RootFiles {
		p, _ := m.itemPath(x)
		n, e := m.fs.inspect(p)
		if e != nil || !equalNode(n, x.Node) {
			return ErrUnknown
		}
		b, e := m.fs.read(p, n, 128<<20)
		if e != nil || digest(b) != x.Hash {
			return ErrUnknown
		}
	}
	for _, x := range j.Directories {
		if x.Scope == "program" {
			p, _ := m.itemPath(x)
			n, e := m.fs.inspect(p)
			if e != nil || !equalNode(n, x.Node) {
				return ErrUnknown
			}
		}
	}
	return nil
}
func (m *Manager) uninstall(ctx context.Context) (err error) {
	guard, e := m.control()
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, guard.Close()) }()
	c, cn, e := m.loadLaunch()
	if e != nil {
		return e
	}
	if c.Phase == "installing-disabled" || c.Phase == "cancelling-disabled" {
		return m.cancelInstallation(ctx, c, cn)
	}
	j, jn, e := m.loadJournal()
	l := paths(m.target)
	l.CAEnabled = c.Installation.CASHA256 != ""
	if c.Phase == "removed-disabled" && errors.Is(e, os.ErrNotExist) {
		return m.finishRemoved(ctx, c)
	}
	if e == nil && j.Installation != c.Installation {
		return ErrUnknown
	}
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e == nil {
		if j.Phase == "preparing" {
			if v := m.checkRoot(j); v != nil {
				return v
			}
		} else if v := m.verifyPlan(j); v != nil {
			return v
		}
	} else {
		r, v := m.verify()
		if v != nil || r != c.Installation {
			return ErrUnknown
		}
		if _, _, v = m.ownedLaunch(r); v != nil {
			return v
		}
		if _, v = m.stateEntries(l.State, false); v != nil {
			return v
		}
	}
	if c.Phase != "uninstalling-disabled" && c.Phase != "removed-disabled" {
		c.Phase = "uninstalling-disabled"
		cn, e = m.saveLaunch(c, &cn)
		if e != nil {
			return e
		}
	}
	if e = m.gate(ctx, l, true); e != nil {
		return e
	}
	if errors.Is(e, os.ErrNotExist) {
		return ErrUnknown
	}
	// journal存在时目录可能已freeze；只正常停原job，不依赖IPC，之后正式offline动作恢复。
	if j.Version != 0 {
		if e = m.stopOwned(ctx, l, true); e != nil {
			return e
		}
	} else {
		if e = m.stopForUninstall(ctx, l); e != nil {
			return e
		}
		j, e = m.prepareJournal(c.Installation)
		if e != nil {
			return e
		}
		jn, e = m.saveJournal(j, nil)
		if e != nil {
			return e
		}
	}
	if e = m.ensureAbsent(ctx, l); e != nil {
		return e
	}
	var g *frozenScope
	if j.Phase == "preparing" {
		if e = m.checkRoot(j); e != nil {
			return e
		}
		g, xs, v := m.freeze(j)
		if v != nil {
			return v
		}
		retainFrozen := false
		defer func() { err = errors.Join(err, g.close(!retainFrozen)) }()
		if len(xs) != 1 || len(g.dirs) != 1 {
			if e = g.close(true); e != nil {
				return e
			}
			local, ok := m.runner.(localRunner)
			if !ok {
				return ErrUnknown
			}
			if e = local.offlineLogout(ctx, l, m.target); e != nil {
				return e
			}
			if e = m.ensureAbsent(ctx, l); e != nil {
				return e
			}
			g, xs, v = m.freeze(j)
			if v != nil {
				return v
			}
		}
		for _, x := range xs {
			if accountFile(x.Name) {
				return ErrUnknown
			}
		}
		if e = m.checkRoot(j); e != nil {
			return e
		}
		j.Phase = "cleanup-authorized"
		j.Plan = cleanupOrder(append(append([]item{}, xs...), j.RootFiles...))
		for _, x := range j.Directories {
			if x.Scope == "program" {
				j.Plan = cleanupOrder(append(j.Plan, x))
			}
		}
		retainFrozen = true // 即便 publish/Sync 失败，preparing 也能恢复该精确冻结状态。
		jn, e = m.saveJournal(j, &jn)
		if e != nil {
			return e
		}
		return m.cleanup(ctx, l, j, jn, g)
	}
	if e = m.verifyPlan(j); e != nil {
		return e
	}
	g = &frozenScope{m: m}
	defer func() { err = errors.Join(err, g.close(false)) }()
	for _, x := range j.Plan {
		if (x.Scope == "state" && x.Name == "vault.lock") || (x.Scope == "ipc" && x.Name == "ipc.lock") {
			p, _ := m.itemPath(x)
			if n, e := m.fs.inspect(p); e == nil {
				h, e := m.fs.claimLock(p, n)
				if e != nil {
					return e
				}
				g.locks = append(g.locks, h)
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			}
		}
	}
	return m.cleanup(ctx, l, j, jn, g)
}
func (m *Manager) verifyPlan(j journal) error {
	exists := map[string]bool{}
	for i, x := range j.Plan {
		p, _ := m.itemPath(x)
		n, e := m.fs.inspect(p)
		if errors.Is(e, os.ErrNotExist) {
			if i <= j.Next {
				continue
			}
			return ErrUnknown
		}
		if e != nil || i < j.Next || !equalNode(n, x.Node) {
			return ErrUnknown
		}
		exists[p] = true
		if n.Kind == regular {
			b, e := m.fs.read(p, n, 128<<20)
			if e != nil || digest(b) != x.Hash {
				return ErrUnknown
			}
			clear(b)
		}
	}
	for _, x := range j.Plan {
		if x.Node.Kind != directory {
			continue
		}
		p, _ := m.itemPath(x)
		if !exists[p] {
			continue
		}
		children, e := m.fs.children(p)
		if e != nil {
			return e
		}
		for _, child := range children {
			if !exists[p+"/"+child.Name] {
				return ErrUnknown
			}
		}
	}
	return nil
}
func (m *Manager) cleanup(ctx context.Context, l layout, j journal, jn node, _ *frozenScope) error {
	for j.Next < len(j.Plan) {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := m.ensureAbsent(ctx, l); e != nil {
			return e
		}
		if e := m.verifyPlan(j); e != nil {
			return e
		}
		x := j.Plan[j.Next]
		p, _ := m.itemPath(x)
		if _, e := m.fs.inspect(p); e == nil {
			if e = m.fs.remove(p, x.Node); e != nil {
				return e
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} else {
			// unlink 可能已发生但父目录尚未同步；缺失本身不能授权推进持久cursor。
			f, ok := m.fs.(absenceFS)
			if !ok {
				return ErrUnknown
			}
			if e = f.durableAbsence(p); e != nil {
				return e
			}
		}
		j.Next++
		n, e := m.saveJournal(j, &jn)
		if e != nil {
			return e
		}
		jn = n
	}
	if e := m.ensureAbsent(ctx, l); e != nil {
		return e
	}
	if e := m.verifyPlan(j); e != nil {
		return e
	}
	if e := m.markRemoved(j.Installation); e != nil {
		return e
	}
	return m.fs.remove(l.Journal, jn)
}
