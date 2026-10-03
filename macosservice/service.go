// Package macosservice 提供不覆盖旧安装的有限 macOS 服务安装入口。
package macosservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/harmonia-vault/core-go/platform"
)

var (
	ErrUnsafe   = errors.New("文件、目录或身份不安全；没有继续操作")
	ErrConflict = errors.New("已有安装、未知文件或服务冲突；不覆盖")
	ErrUnknown  = errors.New("操作结果不明或材料已改变；保留资料停止")
)

type Target struct {
	UserName string
	UID, GID uint32
}

type identity struct{ Name, UID, GID string }

func matchingIdentity(t Target, byName, byUID identity) bool {
	u := strconv.FormatUint(uint64(t.UID), 10)
	g := strconv.FormatUint(uint64(t.GID), 10)
	return byName.Name == t.UserName && byUID.Name == t.UserName && byName.UID == u && byUID.UID == u && byName.GID == g && byUID.GID == g
}

type InstallOptions struct{ Binary, BinarySHA256, CAFile string }
type kind uint8

const (
	regular kind = iota
	directory
	socket
	other
)

type node struct {
	Kind   kind   `json:"kind"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Links  uint64 `json:"links"`
	ACL    bool   `json:"acl"`
}

func (n node) same(o node) bool {
	return n.Device == o.Device && n.Inode == o.Inode && n.Kind == o.Kind
}

type entry struct {
	Name string
	Node node
}
type fileSystem interface {
	inspect(string) (node, error)
	read(string, node, int) ([]byte, error)
	mkdir(string, uint32, uint32, uint32) (node, error)
	write(string, []byte, uint32) (node, error)
	children(string) ([]entry, error)
	remove(string, node) error
	owner(string, node, uint32, uint32) (node, error)
	claimLock(string, node) (io.Closer, error)
}
type serviceState uint8

const (
	absent serviceState = iota
	matching
	unknown
)

type commandRunner interface {
	state(context.Context, layout, Target) (serviceState, error)
	bootstrap(context.Context, layout) error
	bootout(context.Context, layout) error
	logout(context.Context, layout, Target) error
	controlledPID(context.Context, layout, Target) (int, error)
	waitExit(context.Context, int) error
}
type layout struct {
	Program, State, Plist, Binary, Receipt, CA, Label, Control, Journal string
	CAEnabled                                                           bool
}

func paths(t Target) layout {
	u := strconv.FormatUint(uint64(t.UID), 10)
	p := "/usr/local/lib/harmonia/" + u
	l := "org.harmonia-vault.user." + u
	return layout{Program: p, State: "/Library/Application Support/Harmonia/" + u, Plist: "/Library/LaunchDaemons/" + l + ".plist", Binary: p + "/harmonia", Receipt: p + "/installation.json", CA: p + "/ca.pem", Label: l, Control: "/usr/local/lib/harmonia/" + u + ".control.lock", Journal: "/usr/local/lib/harmonia/" + u + ".uninstall.json"}
}

type receipt struct {
	InstallationID string `json:"installationID"`
	Version        int    `json:"version"`
	UserName       string `json:"userName"`
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	BinarySHA256   string `json:"binarySHA256"`
	CASHA256       string `json:"caSHA256,omitempty"`
}

// Manager 的生产构造器只接受真实 Darwin/root 与双向核对过的目标账号。
type Manager struct {
	target Target
	fs     fileSystem
	runner commandRunner
}

func (m *Manager) StateDirectory() string { return paths(m.target).State }
func (m *Manager) BinaryPath() string     { return paths(m.target).Binary }
func (m *Manager) checkedFile(p string, uid uint32, mode uint32) (node, error) {
	n, e := m.fs.inspect(p)
	if e != nil {
		return n, e
	}
	if n.Kind != regular || n.UID != uid || n.Mode != mode || n.Links != 1 || n.ACL {
		return n, ErrUnsafe
	}
	return n, nil
}
func (m *Manager) checkedDir(p string, uid uint32, mode uint32) (node, error) {
	n, e := m.fs.inspect(p)
	if e != nil {
		return n, e
	}
	if n.Kind != directory || n.UID != uid || n.Mode != mode || n.ACL || (uid == m.target.UID && n.GID != m.target.GID) {
		return n, ErrUnsafe
	}
	return n, nil
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (m *Manager) source(p string, max int, executable bool) ([]byte, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return nil, ErrUnsafe
	}
	// 来源与 target 可写状态的权限角色不同：每个来源祖先必须只由 root 管理。
	for parent := filepath.Dir(p); ; parent = filepath.Dir(parent) {
		n, e := m.fs.inspect(parent)
		if e != nil {
			return nil, e
		}
		if n.Kind != directory || n.UID != 0 || n.Mode&022 != 0 || n.ACL {
			return nil, ErrUnsafe
		}
		if parent == "/" {
			break
		}
	}
	n, e := m.fs.inspect(p)
	if e != nil {
		return nil, e
	}
	if n.Kind != regular || n.UID != 0 || n.Links != 1 || n.ACL || n.Mode&06022 != 0 || (executable && n.Mode&0111 == 0) {
		return nil, ErrUnsafe
	}
	return m.fs.read(p, n, max)
}

func readableByTarget(n node, t Target) bool {
	// 正式 Vault 使用 O_RDONLY 打开每个祖先；只给 execute 不足以运行。
	if n.GID == t.GID {
		return n.Mode&0050 == 0050
	}
	return n.Mode&0005 == 0005
}
func publicCA(b []byte) bool {
	count := 0
	for len(bytes.TrimSpace(b)) > 0 {
		b = bytes.TrimSpace(b)
		if !bytes.HasPrefix(b, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		c, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !c.IsCA {
			return false
		}
		count++
		b = rest
	}
	return count > 0
}
func (m *Manager) plist(r receipt) ([]byte, error) {
	l := paths(m.target)
	c := platform.ServiceConfig{UserName: m.target.UserName, UserID: strconv.FormatUint(uint64(m.target.UID), 10), BinaryPath: l.Binary, StateDirectory: l.State}
	if r.CASHA256 != "" {
		c.CAFile = l.CA
	}
	t, e := platform.LaunchDaemon(c)
	return t.Content, e
}

type created struct {
	path string
	node node
}

func (m *Manager) rollback(xs []created) error {
	var all error
	for i := len(xs) - 1; i >= 0; i-- {
		all = errors.Join(all, m.fs.remove(xs[i].path, xs[i].node))
	}
	return all
}

// Install 仅新建固定范围，不启动服务、不建立设备信任、不覆盖已有对象。
func (m *Manager) Install(ctx context.Context, o InstallOptions) error { return m.install(ctx, o) }
func (m *Manager) verifyRoot() (receipt, error) {
	l := paths(m.target)
	var r receipt
	if _, e := m.checkedDir(l.Program, 0, 0755); e != nil {
		return r, e
	}
	n, e := m.checkedFile(l.Receipt, 0, 0644)
	if e != nil {
		return r, e
	}
	b, e := m.fs.read(l.Receipt, n, 4096)
	if e != nil {
		return r, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Version != 2 || !installationPattern.MatchString(r.InstallationID) || r.UserName != m.target.UserName || r.UID != m.target.UID || r.GID != m.target.GID || !hashPattern.MatchString(r.BinarySHA256) || (r.CASHA256 != "" && !hashPattern.MatchString(r.CASHA256)) {
		return r, ErrUnknown
	}
	canonical, e := json.Marshal(r)
	if e != nil || !bytes.Equal(b, append(canonical, '\n')) {
		return r, ErrUnknown
	}
	allowed := map[string]uint32{"harmonia": 0755, "installation.json": 0644}
	if r.CASHA256 != "" {
		allowed["ca.pem"] = 0644
	}
	xs, e := m.fs.children(l.Program)
	if e != nil {
		return r, e
	}
	if len(xs) != len(allowed) {
		return r, ErrUnknown
	}
	for _, x := range xs {
		mode, ok := allowed[x.Name]
		if !ok || x.Node.Kind != regular || x.Node.UID != 0 || x.Node.Mode != mode || x.Node.Links != 1 || x.Node.ACL {
			return r, ErrUnknown
		}
	}
	n, e = m.checkedFile(l.Binary, 0, 0755)
	if e != nil {
		return r, e
	}
	b, e = m.fs.read(l.Binary, n, 128<<20)
	if e != nil || digest(b) != r.BinarySHA256 {
		return r, ErrUnknown
	}
	if r.CASHA256 != "" {
		n, e = m.checkedFile(l.CA, 0, 0644)
		if e != nil {
			return r, e
		}
		b, e = m.fs.read(l.CA, n, 1<<20)
		if e != nil || digest(b) != r.CASHA256 || !publicCA(b) {
			return r, ErrUnknown
		}
	}
	n, e = m.checkedFile(l.Plist, 0, 0644)
	if e != nil {
		return r, e
	}
	b, e = m.fs.read(l.Plist, n, 16<<10)
	if e != nil {
		return r, e
	}
	expected, e := m.plist(r)
	if e != nil || !bytes.Equal(b, expected) {
		return r, ErrUnknown
	}
	return r, nil
}
func (m *Manager) verify() (receipt, error) {
	r, e := m.verifyRoot()
	if e != nil {
		return r, e
	}
	_, e = m.checkedDir(paths(m.target).State, m.target.UID, 0700)
	return r, e
}
func (m *Manager) Start(ctx context.Context) (err error) {
	guard, e := m.control()
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, guard.Close()) }()
	if e = m.noTransaction(); e != nil {
		return e
	}
	r, e := m.verify()
	if e != nil {
		return e
	}
	c, cn, e := m.ownedLaunch(r)
	if e != nil {
		return e
	}
	if c.Phase == "uninstalling-disabled" {
		return ErrConflict
	}
	l := paths(m.target)
	l.CAEnabled = r.CASHA256 != ""
	state, e := m.runner.state(ctx, l, m.target)
	if e != nil || state == unknown {
		return ErrUnknown
	}
	// 已完成且本来enabled的受控job仅返回状态，不重新授予enable。
	if state == matching && c.Phase == "installed-enabled" {
		lr, ok := m.runner.(launchRunner)
		if !ok {
			return ErrUnknown
		}
		present, disabled, e := lr.disabled(ctx, l)
		if e != nil || !present {
			return ErrUnknown
		}
		if !disabled {
			return nil
		}
	}
	// start-authorized返回不明必须正常停/drain，再核成熟本地来源，不能借运行状态重enable。

	if state == matching {
		if e = m.gate(ctx, l, true); e != nil {
			return e
		}
		if e = m.stopOwned(ctx, l, true); e != nil {
			return e
		}
	}
	if _, e = m.stateEntries(l.State, false); e != nil {
		return e
	}
	local, ok := m.runner.(localRunner)
	if !ok {
		return ErrUnknown
	}
	if e = local.enrollmentCheck(ctx, l, m.target); e != nil {
		return e
	}
	c.Phase = "start-authorized"
	cn, e = m.saveLaunch(c, &cn)
	if e != nil {
		return e
	}
	fail := func(cause error) error {
		c.Phase = "installed-disabled"
		_, se := m.saveLaunch(c, &cn)
		return errors.Join(cause, se, m.gate(ctx, l, true))
	}
	if e = m.gate(ctx, l, false); e != nil {
		return fail(e)
	}
	if e = m.runner.bootstrap(ctx, l); e != nil {
		return fail(e)
	}
	state, e = m.runner.state(ctx, l, m.target)
	if e != nil || state != matching {
		return fail(ErrUnknown)
	}
	c.Phase = "installed-enabled"
	_, e = m.saveLaunch(c, &cn)
	return e
}
func (m *Manager) Stop(ctx context.Context) (err error) {
	guard, e := m.control()
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, guard.Close()) }()
	c, cn, e := m.loadLaunch()
	if e != nil {
		return e
	}
	l := paths(m.target)
	l.CAEnabled = c.Installation.CASHA256 != ""
	j, _, je := m.loadJournal()
	if je == nil {
		if j.Installation != c.Installation {
			return ErrUnknown
		}
		if j.Phase == "preparing" {
			if e = m.checkRoot(j); e != nil {
				return e
			}
		} else if e = m.verifyPlan(j); e != nil {
			return e
		}
	} else if !errors.Is(je, os.ErrNotExist) {
		return je
	} else {
		if c.Phase == "installing-disabled" || c.Phase == "cancelling-disabled" || c.Phase == "removed-disabled" {
			return ErrConflict
		}
		r, e := m.verify()
		if e != nil || r != c.Installation {
			return ErrUnknown
		}
		if _, _, e = m.ownedLaunch(r); e != nil {
			return e
		}
		c.Phase = "installed-disabled"
		cn, e = m.saveLaunch(c, &cn)
		if e != nil {
			return e
		}
	}
	if e = m.gate(ctx, l, true); e != nil {
		return e
	}
	return m.stopOwned(ctx, l, true)
}

var stateFiles = map[string]bool{"machine-key.v1": true, "vault.lock": true, "state.v1.enc": true, "device.v1.enc": true, "session.v1.enc": true, "trust.v1.enc": true, "provider.v1.enc": true, "writes.v1.enc": true, "environment.sh": true, "recovery.dag.v1.enc": true}

func (m *Manager) stateEntries(p string, ipc bool) ([]entry, error) {
	xs, e := m.fs.children(p)
	if e != nil {
		return nil, e
	}
	for _, x := range xs {
		if x.Node.ACL || x.Node.UID != m.target.UID {
			return nil, ErrUnknown
		}
		if !ipc && x.Name == "ipc" {
			if x.Node.Kind != directory || x.Node.Mode != 0700 {
				return nil, ErrUnknown
			}
			if _, e = m.stateEntries(p+"/ipc", true); e != nil {
				return nil, e
			}
			continue
		}
		valid := stateFiles[x.Name] && !ipc
		if ipc {
			valid = x.Name == "ipc.lock" || x.Name == "harmonia.sock"
		}
		if !valid || x.Node.Mode != 0600 || (x.Node.Kind != regular && !(ipc && x.Name == "harmonia.sock" && x.Node.Kind == socket)) || (x.Node.Kind == regular && x.Node.Links != 1) {
			return nil, ErrUnknown
		}
	}
	return xs, nil
}

// Uninstall 使用持久清理意图；停止状态、空安装和部分清理可安全重试。
func (m *Manager) Uninstall(ctx context.Context) error { return m.uninstall(ctx) }

func validateTarget(t Target) error {
	if t.UID == 0 || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`).MatchString(t.UserName) || t.UserName == "root" {
		return fmt.Errorf("%w: 必须明确非 root 本地目标账号", ErrUnsafe)
	}
	return nil
}

var installationPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var stagePattern = regexp.MustCompile(`^\.harmonia\.[0-9]+\.stage\.[a-f0-9]{32}$`)
