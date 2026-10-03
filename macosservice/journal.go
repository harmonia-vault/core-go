package macosservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type journalFS interface {
	publish(string, *node, []byte) (node, error)
	durable(string, node) error
}
type item struct {
	Scope string `json:"scope"`
	Name  string `json:"name"`
	Node  node   `json:"node"`
	Hash  string `json:"sha256,omitempty"`
}
type journal struct {
	Version      int     `json:"version"`
	Installation receipt `json:"installation"`
	Phase        string  `json:"phase"`
	Directories  []item  `json:"directories"`
	RootFiles    []item  `json:"rootFiles"`
	Plan         []item  `json:"plan"`
	Next         int     `json:"next"`
}

func (m *Manager) itemPath(x item) (string, error) {
	l := paths(m.target)
	switch x.Scope {
	case "state":
		if x.Name == "" {
			return l.State, nil
		}
		if stateFiles[x.Name] {
			return l.State + "/" + x.Name, nil
		}
	case "ipc":
		if x.Name == "" {
			return l.State + "/ipc", nil
		}
		if x.Name == "ipc.lock" || x.Name == "harmonia.sock" {
			return l.State + "/ipc/" + x.Name, nil
		}
	case "program":
		if x.Name == "" {
			return l.Program, nil
		}
		if x.Name == "harmonia" || x.Name == "installation.json" || x.Name == "ca.pem" {
			return l.Program + "/" + x.Name, nil
		}
	case "plist":
		if x.Name == "" {
			return l.Plist, nil
		}
	}
	return "", ErrUnknown
}
func equalNode(a, b node) bool {
	if a.Kind == directory && b.Kind == directory {
		a.Links = 0
		b.Links = 0
	}
	return a == b
}
func (m *Manager) validJournal(j journal) error {
	r := j.Installation
	if j.Version != 1 || r.Version != 2 || !installationPattern.MatchString(r.InstallationID) || r.UID != m.target.UID || r.GID != m.target.GID || r.UserName != m.target.UserName || !hashPattern.MatchString(r.BinarySHA256) || (r.CASHA256 != "" && !hashPattern.MatchString(r.CASHA256)) {
		return ErrUnknown
	}
	if len(j.Directories) < 2 || len(j.Directories) > 3 || len(j.RootFiles) < 3 || len(j.RootFiles) > 4 {
		return ErrUnknown
	}
	seen := map[string]bool{}
	for _, x := range j.Directories {
		p, e := m.itemPath(x)
		if e != nil || seen[p] || x.Name != "" || x.Node.Kind != directory || x.Node.ACL || x.Hash != "" || x.Node.Device == 0 || x.Node.Inode == 0 {
			return ErrUnknown
		}
		seen[p] = true
		if x.Scope == "program" {
			if x.Node.UID != 0 || x.Node.GID != 0 || x.Node.Mode != 0755 {
				return ErrUnknown
			}
		} else if (x.Scope != "state" && x.Scope != "ipc") || x.Node.UID != m.target.UID || x.Node.GID != m.target.GID || x.Node.Mode != 0700 {
			return ErrUnknown
		}
	}
	l := paths(m.target)
	if !seen[l.Program] || !seen[l.State] {
		return ErrUnknown
	}
	rootAllowed := map[string]string{l.Binary: r.BinarySHA256}
	b, _ := json.Marshal(r)
	rootAllowed[l.Receipt] = digest(append(b, '\n'))
	b, e := m.plist(r)
	if e != nil {
		return e
	}
	rootAllowed[l.Plist] = digest(b)
	if r.CASHA256 != "" {
		rootAllowed[l.CA] = r.CASHA256
	}
	if len(rootAllowed) != len(j.RootFiles) {
		return ErrUnknown
	}
	for _, x := range j.RootFiles {
		p, e := m.itemPath(x)
		h, ok := rootAllowed[p]
		mode := uint32(0644)
		if p == l.Binary {
			mode = 0755
		}
		if e != nil || !ok || seen[p] || x.Hash != h || x.Node.Kind != regular || x.Node.UID != 0 || x.Node.GID != 0 || x.Node.Mode != mode || x.Node.Links != 1 || x.Node.ACL || x.Node.Inode == 0 || x.Node.Device == 0 {
			return ErrUnknown
		}
		seen[p] = true
	}
	if j.Phase == "preparing" {
		if j.Next != 0 || j.Plan != nil {
			return ErrUnknown
		}
		return nil
	}
	if j.Phase != "cleanup-authorized" || len(j.Plan) < 5 || len(j.Plan) > 32 || j.Next < 0 || j.Next > len(j.Plan) {
		return ErrUnknown
	}
	seen = map[string]bool{}
	for _, x := range j.Plan {
		p, e := m.itemPath(x)
		if e != nil || seen[p] || x.Node.ACL || x.Node.Device == 0 || x.Node.Inode == 0 {
			return ErrUnknown
		}
		seen[p] = true
		if x.Node.Kind == directory {
			if x.Name != "" || x.Node.UID != 0 || x.Node.GID != 0 || x.Hash != "" {
				return ErrUnknown
			}
			found := false
			for _, d := range j.Directories {
				if d.Scope == x.Scope && d.Node.same(x.Node) {
					found = true
				}
			}
			if !found || (x.Scope == "program" && x.Node.Mode != 0755) || (x.Scope != "program" && x.Node.Mode != 0700) {
				return ErrUnknown
			}
		} else if x.Scope == "state" || x.Scope == "ipc" {
			if x.Node.UID != m.target.UID || x.Node.Mode != 0600 || (x.Node.Kind == regular && (x.Node.Links != 1 || !hashPattern.MatchString(x.Hash))) || (x.Node.Kind == socket && (x.Scope != "ipc" || x.Name != "harmonia.sock" || x.Hash != "")) || (x.Node.Kind != regular && x.Node.Kind != socket) {
				return ErrUnknown
			}
			if accountFile(x.Name) {
				return ErrUnknown
			}
		} else {
			found := false
			for _, r := range j.RootFiles {
				if r == x {
					found = true
				}
			}
			if !found {
				return ErrUnknown
			}
		}
	}
	// 所有固定 root 项/目录必须完整出现；顺序只由本函数的有限排序决定。
	for _, x := range append(append([]item{}, j.RootFiles...), j.Directories...) {
		p, _ := m.itemPath(x)
		if !seen[p] {
			return ErrUnknown
		}
	}
	hasStateData := false
	for _, x := range j.Plan {
		if (x.Scope == "state" && x.Name != "") || x.Scope == "ipc" {
			hasStateData = true
		}
	}
	if hasStateData && !seen[l.State+"/vault.lock"] {
		return ErrUnknown
	}
	if seen[l.State+"/ipc"] && !seen[l.State+"/ipc/ipc.lock"] {
		return ErrUnknown
	}
	ordered := cleanupOrder(j.Plan)
	if len(ordered) != len(j.Plan) {
		return ErrUnknown
	}
	for i := range ordered {
		if ordered[i] != j.Plan[i] {
			return ErrUnknown
		}
	}
	return nil
}
func (m *Manager) loadJournal() (journal, node, error) {
	l := paths(m.target)
	n, e := m.checkedFile(l.Journal, 0, 0600)
	if e != nil {
		return journal{}, node{}, e
	}
	if n.GID != 0 {
		return journal{}, node{}, ErrUnknown
	}
	b, e := m.fs.read(l.Journal, n, 64<<10)
	if e != nil {
		return journal{}, node{}, e
	}
	var j journal
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF {
		return j, n, ErrUnknown
	}
	canonical, e := json.Marshal(j)
	if e != nil || !bytes.Equal(b, append(canonical, '\n')) {
		return j, n, ErrUnknown
	}
	if e = m.validJournal(j); e != nil {
		return j, n, e
	}
	f, ok := m.fs.(journalFS)
	if !ok {
		return j, n, ErrUnknown
	}
	if e = f.durable(l.Journal, n); e != nil {
		return j, n, e
	}
	return j, n, nil
}
func (m *Manager) saveJournal(j journal, old *node) (node, error) {
	if e := m.validJournal(j); e != nil {
		return node{}, e
	}
	f, ok := m.fs.(journalFS)
	if !ok {
		return node{}, ErrUnknown
	}
	b, e := json.Marshal(j)
	if e != nil {
		return node{}, e
	}
	return f.publish(paths(m.target).Journal, old, append(b, '\n'))
}
func (m *Manager) noTransaction() error {
	_, e := m.fs.inspect(paths(m.target).Journal)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	return ErrConflict
}
func (m *Manager) control() (io.Closer, error) {
	l := paths(m.target)
	parent, e := m.fs.inspect(filepath.Dir(l.Control))
	if e != nil {
		return nil, e
	}
	if parent.Kind != directory || parent.UID != 0 || parent.Mode&022 != 0 || parent.ACL {
		return nil, ErrUnsafe
	}
	n, e := m.fs.inspect(l.Control)
	if errors.Is(e, os.ErrNotExist) {
		f, ok := m.fs.(journalFS)
		if !ok {
			return nil, ErrUnknown
		}
		n, e = f.publish(l.Control, nil, nil)
	}
	if e != nil {
		return nil, e
	}
	if n.Kind != regular || n.UID != 0 || n.GID != 0 || n.Mode != 0600 || n.Links != 1 || n.ACL {
		return nil, ErrUnknown
	}
	if b, e := m.fs.read(l.Control, n, 0); e != nil || len(b) != 0 {
		return nil, ErrUnknown
	}
	return m.fs.claimLock(l.Control, n)
}
