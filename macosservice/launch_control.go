package macosservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type creation struct {
	Scope       string `json:"scope"`
	Stage       string `json:"stage"`
	Parent      node   `json:"parent"`
	FinalParent node   `json:"finalParent"`
	Node        node   `json:"node"`
	Hash        string `json:"sha256,omitempty"`
}
type launchControl struct {
	Version      int        `json:"version"`
	Installation receipt    `json:"installation"`
	Phase        string     `json:"phase"`
	Created      []creation `json:"created"`
	Next         int        `json:"next"`
}
type creationFS interface {
	prepareCreation(string, string, []byte, uint32, uint32, uint32, bool) (creation, error)
	commitCreation(string, string, creation) error
	childrenCreated(string, node) ([]entry, error)
}
type jobSnapshot struct {
	State       serviceState
	PID         int
	StableNoPID bool
}
type launchRunner interface {
	disabled(context.Context, layout) (bool, bool, error)
	setDisabled(context.Context, layout, bool) error
	observeJob(context.Context, layout, Target) (jobSnapshot, error)
}

func launchPath(l layout) string {
	return filepath.Dir(l.Control) + "/" + filepath.Base(l.Program) + ".launch-control.json"
}
func (m *Manager) creationPath(scope string) (string, string, error) {
	l := paths(m.target)
	switch scope {
	case "program":
		return l.Program, filepath.Dir(l.Program), nil
	case "state":
		return l.State, filepath.Dir(l.State), nil
	case "binary":
		return l.Binary, filepath.Dir(l.Program), nil
	case "ca":
		return l.CA, filepath.Dir(l.Program), nil
	case "receipt":
		return l.Receipt, filepath.Dir(l.Program), nil
	case "plist":
		return l.Plist, filepath.Dir(l.Plist), nil
	}
	return "", "", ErrUnknown
}
func expectedScopes(r receipt) []string {
	scopes := []string{"program", "state", "binary"}
	if r.CASHA256 != "" {
		scopes = append(scopes, "ca")
	}
	return append(scopes, "receipt", "plist")
}
func (m *Manager) creationHash(r receipt, scope string) (string, error) {
	switch scope {
	case "program", "state":
		return "", nil
	case "binary":
		return r.BinarySHA256, nil
	case "ca":
		return r.CASHA256, nil
	case "receipt":
		b, e := json.Marshal(r)
		return digest(append(b, '\n')), e
	case "plist":
		b, e := m.plist(r)
		return digest(b), e
	}
	return "", ErrUnknown
}
func (m *Manager) validLaunch(c launchControl) error {
	r := c.Installation
	if c.Version != 1 || r.Version != 2 || r.UID != m.target.UID || r.GID != m.target.GID || r.UserName != m.target.UserName || !installationPattern.MatchString(r.InstallationID) || !hashPattern.MatchString(r.BinarySHA256) || (r.CASHA256 != "" && !hashPattern.MatchString(r.CASHA256)) {
		return ErrUnknown
	}
	switch c.Phase {
	case "installing-disabled", "installed-disabled", "start-authorized", "installed-enabled", "uninstalling-disabled", "cancelling-disabled", "removed-disabled":
	default:
		return ErrUnknown
	}
	scopes := expectedScopes(r)
	if len(c.Created) > len(scopes) || c.Next < 0 || c.Next > len(c.Created) {
		return ErrUnknown
	}
	if c.Phase != "cancelling-disabled" && c.Phase != "removed-disabled" && c.Next != 0 {
		return ErrUnknown
	}
	if c.Phase != "installing-disabled" && c.Phase != "cancelling-disabled" && c.Phase != "removed-disabled" && len(c.Created) != len(scopes) {
		return ErrUnknown
	}
	for i, x := range c.Created {
		if x.Scope != scopes[i] || !stagePattern.MatchString(x.Stage) || !bytes.HasPrefix([]byte(x.Stage), []byte(".harmonia."+filepath.Base(paths(m.target).Program)+".stage.")) {
			return ErrUnknown
		}
		if x.Node.Device == 0 || x.Node.Inode == 0 || x.Node.ACL {
			return ErrUnknown
		}
		uid, gid, mode, k := uint32(0), uint32(0), uint32(0644), regular
		if x.Scope == "program" {
			mode, k = 0755, directory
		}
		if x.Scope == "state" {
			uid, gid, mode, k = m.target.UID, m.target.GID, 0700, directory
		}
		if x.Scope == "binary" {
			mode = 0755
		}
		h, e := m.creationHash(r, x.Scope)
		if e != nil || x.Hash != h || x.Node.Kind != k || x.Node.UID != uid || x.Node.GID != gid || x.Node.Mode != mode || (k == regular && x.Node.Links != 1) {
			return ErrUnknown
		}
		for _, p := range []node{x.Parent, x.FinalParent} {
			if p.Kind != directory || p.UID != 0 || p.Mode&022 != 0 || p.ACL || p.Device == 0 || p.Inode == 0 || !readableByTarget(p, m.target) {
				return ErrUnknown
			}
		}
		if x.Scope == "binary" || x.Scope == "receipt" || x.Scope == "ca" {
			if len(c.Created) == 0 || !equalNode(x.FinalParent, c.Created[0].Node) {
				return ErrUnknown
			}
		} else if !equalNode(x.Parent, x.FinalParent) {
			return ErrUnknown
		}
	}
	return nil
}
func (m *Manager) loadLaunch() (launchControl, node, error) {
	p := launchPath(paths(m.target))
	n, e := m.checkedFile(p, 0, 0600)
	if e != nil {
		return launchControl{}, node{}, e
	}
	if n.GID != 0 {
		return launchControl{}, n, ErrUnknown
	}
	b, e := m.fs.read(p, n, 64<<10)
	if e != nil {
		return launchControl{}, n, e
	}
	var c launchControl
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, n, ErrUnknown
	}
	canonical, e := json.Marshal(c)
	if e != nil || !bytes.Equal(b, append(canonical, '\n')) {
		return c, n, ErrUnknown
	}
	if e = m.validLaunch(c); e != nil {
		return c, n, e
	}
	f, ok := m.fs.(journalFS)
	if !ok {
		return c, n, ErrUnknown
	}
	if e = f.durable(p, n); e != nil {
		return c, n, e
	}
	return c, n, nil
}
func (m *Manager) saveLaunch(c launchControl, old *node) (node, error) {
	if e := m.validLaunch(c); e != nil {
		return node{}, e
	}
	f, ok := m.fs.(journalFS)
	if !ok {
		return node{}, ErrUnknown
	}
	b, e := json.Marshal(c)
	if e != nil {
		return node{}, e
	}
	return f.publish(launchPath(paths(m.target)), old, append(b, '\n'))
}
func (m *Manager) gate(ctx context.Context, l layout, disabled bool) error {
	r, ok := m.runner.(launchRunner)
	if !ok {
		return ErrUnknown
	}
	if e := r.setDisabled(ctx, l, disabled); e != nil {
		return e
	}
	present, value, e := r.disabled(ctx, l)
	if e != nil || !present || value != disabled {
		return ErrUnknown
	}
	return nil
}
func (m *Manager) objectLocations(x creation) (string, string, error) {
	p, parent, e := m.creationPath(x.Scope)
	if e != nil {
		return "", "", e
	}
	return p, parent + "/" + x.Stage, nil
}
func (m *Manager) checkCreationAt(x creation, p string) error {
	expected := x.FinalParent
	if filepath.Base(p) == x.Stage {
		expected = x.Parent
	}
	parent, e := m.fs.inspect(filepath.Dir(p))
	if e != nil || !equalNode(parent, expected) {
		return ErrUnknown
	}
	n, e := m.fs.inspect(p)
	if e != nil || !equalNode(n, x.Node) {
		return ErrUnknown
	}
	if n.Kind == regular {
		b, e := m.fs.read(p, n, 128<<20)
		if e != nil || digest(b) != x.Hash {
			return ErrUnknown
		}
	}
	return nil
}
func (m *Manager) ensureCreation(c launchControl, x creation) error {
	f, ok := m.fs.(creationFS)
	if !ok {
		return ErrUnknown
	}
	p, parent, e := m.creationPath(x.Scope)
	if e != nil {
		return e
	}
	return f.commitCreation(p, parent, x)
}
func (m *Manager) ensureParents() error {
	parents := []string{"/usr/local", "/usr/local/lib", "/usr/local/lib/harmonia", "/Library/Application Support/Harmonia"}
	for _, p := range append([]string{"/", "/usr", "/Library", "/Library/Application Support", "/Library/LaunchDaemons"}, parents...) {
		n, e := m.fs.inspect(p)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if n.Kind != directory || n.UID != 0 || n.Mode&022 != 0 || n.ACL || !readableByTarget(n, m.target) {
			return ErrUnsafe
		}
	}
	for _, p := range parents {
		if _, e := m.fs.inspect(p); errors.Is(e, os.ErrNotExist) {
			f, ok := m.fs.(creationFS)
			if !ok {
				return ErrUnknown
			}
			x, e := f.prepareCreation(p, filepath.Dir(p), nil, 0, 0, 0755, true)
			if e != nil {
				return e
			}
			if e = f.commitCreation(p, filepath.Dir(p), x); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
	}
	return nil
}
func (m *Manager) install(ctx context.Context, o InstallOptions) (err error) {
	if !hashPattern.MatchString(o.BinarySHA256) {
		return ErrUnsafe
	}
	binary, e := m.source(o.Binary, 128<<20, true)
	if e != nil {
		return e
	}
	if digest(binary) != o.BinarySHA256 {
		return ErrUnsafe
	}
	var ca []byte
	if o.CAFile != "" {
		ca, e = m.source(o.CAFile, 1<<20, false)
		if e != nil {
			return e
		}
		if !publicCA(ca) {
			return ErrUnsafe
		}
	}
	// 已有未知安装在任何目录/权属写入之前退出。
	before, _, be := m.loadLaunch()
	if be != nil && !errors.Is(be, os.ErrNotExist) {
		return be
	}
	if errors.Is(be, os.ErrNotExist) || before.Phase == "removed-disabled" {
		l := paths(m.target)
		for _, p := range []string{l.Program, l.State, l.Plist} {
			if _, x := m.fs.inspect(p); !errors.Is(x, os.ErrNotExist) {
				return ErrConflict
			}
		}
		state, x := m.runner.state(ctx, l, m.target)
		if x != nil || state != absent {
			return ErrConflict
		}
		lr, ok := m.runner.(launchRunner)
		if !ok {
			return ErrUnknown
		}
		present, _, x := lr.disabled(ctx, l)
		if x != nil {
			return x
		}
		if errors.Is(be, os.ErrNotExist) && present {
			return ErrConflict
		}
	}
	if e = m.ensureParents(); e != nil {
		return e
	}
	guard, e := m.control()
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, guard.Close()) }()
	if e = m.noTransaction(); e != nil {
		return e
	}
	l := paths(m.target)
	c, cn, e := m.loadLaunch()
	fresh := errors.Is(e, os.ErrNotExist)
	if e != nil && !fresh {
		return e
	}
	if fresh || c.Phase == "removed-disabled" {
		for _, p := range []string{l.Program, l.State, l.Plist} {
			if _, e = m.fs.inspect(p); !errors.Is(e, os.ErrNotExist) {
				return ErrConflict
			}
		}
		state, e := m.runner.state(ctx, l, m.target)
		if e != nil || state != absent {
			return ErrConflict
		}
		r, ok := m.runner.(launchRunner)
		if !ok {
			return ErrUnknown
		}
		present, _, e := r.disabled(ctx, l)
		if e != nil {
			return e
		}
		if fresh && present {
			return ErrConflict
		}
		var id [16]byte
		if _, e = rand.Read(id[:]); e != nil {
			return e
		}
		rec := receipt{Version: 2, UserName: m.target.UserName, UID: m.target.UID, GID: m.target.GID, BinarySHA256: o.BinarySHA256, InstallationID: hex.EncodeToString(id[:])}
		if ca != nil {
			rec.CASHA256 = digest(ca)
		}
		c = launchControl{Version: 1, Installation: rec, Phase: "installing-disabled"}
		var old *node
		if !fresh {
			old = &cn
		}
		cn, e = m.saveLaunch(c, old)
		if e != nil {
			return e
		}
	} else if c.Phase != "installing-disabled" && c.Phase != "installed-disabled" {
		return ErrConflict
	}
	if c.Installation.BinarySHA256 != o.BinarySHA256 || c.Installation.CASHA256 != func() string {
		if ca == nil {
			return ""
		}
		return digest(ca)
	}() {
		return ErrConflict
	}
	if c.Phase == "installed-disabled" {
		verified, e := m.verify()
		if e != nil || verified != c.Installation {
			return ErrUnknown
		}
		if _, _, e = m.ownedLaunch(verified); e != nil {
			return e
		}
		if e = m.ensureAbsent(ctx, l); e != nil {
			return e
		}
		return m.gate(ctx, l, true)
	}
	if e = m.gate(ctx, l, true); e != nil {
		return e
	}
	if e = m.ensureAbsent(ctx, l); e != nil {
		return e
	}
	f, ok := m.fs.(creationFS)
	if !ok {
		return ErrUnknown
	}
	scopes := expectedScopes(c.Installation)
	for _, x := range c.Created {
		if e = m.ensureCreation(c, x); e != nil {
			return e
		}
	}
	// 不删除结果不明的stage/已记录inode；普通Install/Uninstall恢复此意图。
	for len(c.Created) < len(scopes) {
		scope := scopes[len(c.Created)]
		p, parent, e := m.creationPath(scope)
		if e != nil {
			return e
		}
		if _, e = m.fs.inspect(p); !errors.Is(e, os.ErrNotExist) {
			return ErrConflict
		}
		e = nil
		var data []byte
		uid, gid, mode, dir := uint32(0), uint32(0), uint32(0644), false
		switch scope {
		case "program":
			mode, dir = 0755, true
		case "state":
			uid, gid, mode, dir = m.target.UID, m.target.GID, 0700, true
		case "binary":
			data, mode = binary, 0755
		case "ca":
			data = ca
		case "receipt":
			data, e = json.Marshal(c.Installation)
			data = append(data, '\n')
		case "plist":
			data, e = m.plist(c.Installation)
		}
		if e != nil {
			return e
		}
		x, e := f.prepareCreation(p, parent, data, uid, gid, mode, dir)
		if e != nil {
			// 仅尚未发布意图的普通创建失败可取消先前已持久对象；失败stage保持inert。
			return errors.Join(e, m.cancelInstallation(ctx, c, cn))
		}
		x.Scope = scope
		h, e := m.creationHash(c.Installation, scope)
		if e != nil {
			return e
		}
		x.Hash = h
		c.Created = append(c.Created, x)
		cn, e = m.saveLaunch(c, &cn)
		if e != nil {
			return e
		}
		if e = m.ensureCreation(c, x); e != nil {
			return e
		}
	}
	// 完整安装才允许开始账号操作；部分取消只允许精确已记录空state。
	if xs, e := m.fs.children(l.State); e != nil || len(xs) != 0 {
		return ErrUnknown
	}
	if e = m.ensureAbsent(ctx, l); e != nil {
		return e
	}
	if verified, e := m.verifyRoot(); e != nil || verified != c.Installation {
		return ErrUnknown
	}
	c.Phase = "installed-disabled"
	_, e = m.saveLaunch(c, &cn)
	return e
}
func (m *Manager) ownedLaunch(r receipt) (launchControl, node, error) {
	c, n, e := m.loadLaunch()
	if e != nil || c.Installation != r || c.Phase == "installing-disabled" || c.Phase == "cancelling-disabled" || c.Phase == "removed-disabled" {
		return c, n, ErrUnknown
	}
	for _, x := range c.Created {
		p, _, e := m.creationPath(x.Scope)
		if e != nil || m.checkCreationAt(x, p) != nil {
			return c, n, ErrUnknown
		}
	}
	return c, n, nil
}
func (m *Manager) stopOwned(ctx context.Context, l layout, allowNoPID bool) error {
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
	owned, _, e := m.loadLaunch()
	if e != nil || len(owned.Created) != len(expectedScopes(owned.Installation)) {
		return ErrUnknown
	}
	if s.State != matching || (s.PID < 2 && (!allowNoPID || !s.StableNoPID)) {
		return ErrUnknown
	}
	if e = m.runner.bootout(ctx, l); e != nil {
		return e
	}
	if e = m.ensureAbsent(ctx, l); e != nil {
		return e
	}
	if s.PID >= 2 {
		return m.runner.waitExit(ctx, s.PID)
	}
	return m.ownerIdle()
}
func (m *Manager) markRemoved(r receipt) error {
	c, n, e := m.loadLaunch()
	if e != nil || c.Installation != r {
		return ErrUnknown
	}
	if c.Phase == "removed-disabled" {
		return nil
	}
	if c.Phase != "uninstalling-disabled" {
		return ErrUnknown
	}
	c.Phase = "removed-disabled"
	_, e = m.saveLaunch(c, &n)
	return e
}

// 未完成安装只清已持久inode和空目录，不碰任何未知账号材料。
func (m *Manager) cancelInstallation(ctx context.Context, c launchControl, cn node) error {
	l := paths(m.target)
	l.CAEnabled = c.Installation.CASHA256 != ""
	if e := m.gate(ctx, l, true); e != nil {
		return e
	}
	if e := m.stopOwned(ctx, l, true); e != nil {
		return e
	}
	if c.Phase == "installing-disabled" {
		c.Phase = "cancelling-disabled"
		c.Next = 0
		var e error
		cn, e = m.saveLaunch(c, &cn)
		if e != nil {
			return e
		}
	}
	f, ok := m.fs.(absenceFS)
	if !ok {
		return ErrUnknown
	}
	for c.Next < len(c.Created) {
		for i, x := range c.Created {
			p, stage, e := m.objectLocations(x)
			if e != nil {
				return e
			}
			rank := len(c.Created) - 1 - i
			found := 0
			for _, path := range []string{p, stage} {
				if _, e = m.fs.inspect(path); e == nil {
					found++
					if rank < c.Next || m.checkCreationAt(x, path) != nil {
						return ErrUnknown
					}
					if x.Node.Kind == directory {
						if e = m.checkPartialChildren(c, x, path); e != nil {
							return e
						}
					}
				} else if !errors.Is(e, os.ErrNotExist) {
					return e
				}
			}
			if found > 1 || found == 0 && rank > c.Next {
				return ErrUnknown
			}
		}
		x := c.Created[len(c.Created)-1-c.Next]
		p, stage, e := m.objectLocations(x)
		if e != nil {
			return e
		}
		for _, path := range []string{p, stage} {
			if _, e = m.fs.inspect(path); e == nil {
				if e = m.fs.remove(path, x.Node); e != nil {
					return e
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			} else if e = f.durableAbsence(path); e != nil {
				return e
			}
		}
		c.Next++
		cn, e = m.saveLaunch(c, &cn)
		if e != nil {
			return e
		}
	}
	c.Phase = "removed-disabled"
	_, e := m.saveLaunch(c, &cn)
	return e
}

func (m *Manager) ownerIdle() (err error) {
	l := paths(m.target)
	j, _, je := m.loadJournal()
	allowedMissing := func(p string) bool {
		if je != nil || j.Phase != "cleanup-authorized" {
			return false
		}
		for i, x := range j.Plan {
			path, _ := m.itemPath(x)
			if path == p {
				return i <= j.Next
			}
		}
		return false
	}
	n, e := m.fs.inspect(l.State)
	if errors.Is(e, os.ErrNotExist) {
		if allowedMissing(l.State) {
			return nil
		}
		return ErrUnknown
	}
	if e != nil || n.Kind != directory || n.Mode != 0700 || n.ACL || !((n.UID == m.target.UID && n.GID == m.target.GID) || (n.UID == 0 && n.GID == 0)) {
		return ErrUnknown
	}
	entries, e := m.fs.children(l.State)
	if e != nil {
		return e
	}
	if len(entries) == 0 {
		return nil
	}
	var held []io.Closer
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			err = errors.Join(err, held[i].Close())
		}
	}()
	for _, p := range []string{l.State + "/vault.lock", l.State + "/ipc/ipc.lock"} {
		if p == l.State+"/ipc/ipc.lock" {
			if _, e := m.fs.inspect(l.State + "/ipc"); errors.Is(e, os.ErrNotExist) {
				continue
			} else if e != nil {
				return e
			}
		}
		n, e := m.checkedFile(p, m.target.UID, 0600)
		if errors.Is(e, os.ErrNotExist) && allowedMissing(p) {
			continue
		}
		if e != nil {
			return e
		}
		h, e := m.fs.claimLock(p, n)
		if e != nil {
			return e
		}
		held = append(held, h)
	}
	return nil
}
func (m *Manager) finishRemoved(ctx context.Context, c launchControl) error {
	l := paths(m.target)
	l.CAEnabled = c.Installation.CASHA256 != ""
	if e := m.gate(ctx, l, true); e != nil {
		return e
	}
	if e := m.ensureAbsent(ctx, l); e != nil {
		return e
	}
	f, ok := m.fs.(absenceFS)
	if !ok {
		return ErrUnknown
	}
	for _, p := range []string{l.Program, l.State, l.Plist, l.Journal} {
		if e := f.durableAbsence(p); e != nil {
			return e
		}
	}
	return nil
}

// 取消前完整确认目录集合，不能删完可信文件后才发现未知用户项。
func (m *Manager) checkPartialChildren(c launchControl, x creation, p string) error {
	f, ok := m.fs.(creationFS)
	if !ok {
		return ErrUnknown
	}
	xs, e := f.childrenCreated(p, x.Node)
	if e != nil {
		return e
	}
	allowed := map[string]creation{}
	if x.Scope == "program" && p == paths(m.target).Program {
		for _, child := range c.Created {
			if child.Scope == "binary" || child.Scope == "ca" || child.Scope == "receipt" {
				final, _, _ := m.creationPath(child.Scope)
				allowed[filepath.Base(final)] = child
			}
		}
	}
	for _, child := range xs {
		expected, ok := allowed[child.Name]
		if !ok || !equalNode(child.Node, expected.Node) {
			return ErrUnknown
		}
	}
	return nil
}
