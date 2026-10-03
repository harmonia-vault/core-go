package macosservice

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type fakeObject struct {
	n    node
	data []byte
}
type fakeFS struct {
	onCommit                                               func(string)
	objects                                                map[string]fakeObject
	next                                                   uint64
	failWrite                                              string
	onOwner                                                func(string)
	removed                                                []string
	busyLock                                               string
	heldLocks                                              map[string]bool
	closedLocks                                            []string
	beforeRemove                                           func(string)
	publishCalls, failPublishAt                            int
	failPublishAfter, durableError                         bool
	onPublish                                              func(string, []byte)
	offlineError, inspectorError                           bool
	onClaim                                                func(string)
	removeCalls, failRemoveAt, ownerCalls, failOwnerAt     int
	failRemoveAfter, failOwnerAfter                        bool
	closeErrorPath                                         string
	volatileRemovals                                       map[string]fakeObject
	failAbsenceSync, failAbsenceClose                      bool
	absenceCalls                                           int
	removeCloseErrorPath                                   string
	launchPublishCalls, failLaunchPublishAt                int
	failLaunchPublishAfter                                 bool
	prepareCalls, failPrepareAt, commitCalls, failCommitAt int
	failCommitAfter                                        bool
}

func (f *fakeFS) add(p string, k kind, uid, gid, mode uint32, b []byte) node {
	f.next++
	n := node{Kind: k, UID: uid, GID: gid, Mode: mode, Device: 1, Inode: f.next, Links: 1}
	f.objects[p] = fakeObject{n, append([]byte(nil), b...)}
	return n
}
func (f *fakeFS) inspect(p string) (node, error) {
	o, ok := f.objects[p]
	if !ok {
		return node{}, os.ErrNotExist
	}
	return o.n, nil
}
func (f *fakeFS) read(p string, n node, max int) ([]byte, error) {
	o, ok := f.objects[p]
	if !ok || !o.n.same(n) {
		return nil, ErrUnknown
	}
	if len(o.data) > max {
		return nil, ErrUnsafe
	}
	return append([]byte(nil), o.data...), nil
}
func (f *fakeFS) mkdir(p string, uid, gid, mode uint32) (node, error) {
	if _, ok := f.objects[p]; ok {
		return node{}, ErrConflict
	}
	if _, ok := f.objects[filepath.Dir(p)]; !ok {
		return node{}, os.ErrNotExist
	}
	return f.add(p, directory, uid, gid, mode, nil), nil
}
func (f *fakeFS) write(p string, b []byte, mode uint32) (node, error) {
	if p == f.failWrite {
		return node{}, errors.New("合成写入失败")
	}
	if _, ok := f.objects[p]; ok {
		return node{}, ErrConflict
	}
	if _, ok := f.objects[filepath.Dir(p)]; !ok {
		return node{}, os.ErrNotExist
	}
	return f.add(p, regular, 0, 0, mode, b), nil
}
func (f *fakeFS) publish(p string, old *node, b []byte) (node, error) {
	// 故障序号与旧卸载journal保持独立。
	launch := len(p) > len(".launch-control.json") && p[len(p)-len(".launch-control.json"):] == ".launch-control.json"
	if launch {
		f.launchPublishCalls++
	} else {
		f.publishCalls++
	}
	failed := (!launch && f.failPublishAt == f.publishCalls) || (launch && f.failLaunchPublishAt == f.launchPublishCalls)
	after := f.failPublishAfter
	if launch {
		after = f.failLaunchPublishAfter
	}
	if f.onPublish != nil {
		f.onPublish(p, b)
	}
	if failed && !after {
		return node{}, ErrUnknown
	}
	existing, e := f.inspect(p)
	if old == nil {
		if !errors.Is(e, os.ErrNotExist) {
			return node{}, ErrConflict
		}
	} else if e != nil || !equalNode(existing, *old) {
		return node{}, ErrUnknown
	}
	n := f.add(p, regular, 0, 0, 0600, b)
	if failed && after {
		return n, ErrUnknown
	}
	return n, nil
}
func (f *fakeFS) durable(p string, n node) error {
	if f.durableError {
		return ErrUnknown
	}
	current, e := f.inspect(p)
	if e != nil || !equalNode(current, n) {
		return ErrUnknown
	}
	return nil
}
func (f *fakeFS) children(p string) ([]entry, error) {
	if _, ok := f.objects[p]; !ok {
		return nil, os.ErrNotExist
	}
	var xs []entry
	for path, o := range f.objects {
		if path != p && filepath.Dir(path) == p {
			xs = append(xs, entry{filepath.Base(path), o.n})
		}
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].Name < xs[j].Name })
	return xs, nil
}
func (f *fakeFS) remove(p string, n node) error {
	f.removeCalls++
	if f.failRemoveAt == f.removeCalls && !f.failRemoveAfter {
		return ErrUnknown
	}
	if f.beforeRemove != nil {
		f.beforeRemove(p)
	}
	o, ok := f.objects[p]
	if !ok || !o.n.same(n) {
		return ErrUnknown
	}
	if o.n.Kind == directory {
		xs, _ := f.children(p)
		if len(xs) > 0 {
			return errors.New("目录非空；保留")
		}
	}
	delete(f.objects, p)
	f.removed = append(f.removed, p)
	if f.failRemoveAt == f.removeCalls && f.failRemoveAfter {
		if f.volatileRemovals != nil {
			f.volatileRemovals[p] = o
		}
		return ErrUnknown
	}
	delete(f.volatileRemovals, p)
	if f.removeCloseErrorPath == p {
		return ErrUnknown
	}
	return nil
}
func (f *fakeFS) owner(p string, n node, uid, gid uint32) (node, error) {
	f.ownerCalls++
	if f.failOwnerAt == f.ownerCalls && !f.failOwnerAfter {
		return node{}, ErrUnknown
	}
	if f.onOwner != nil {
		f.onOwner(p)
	}
	o, ok := f.objects[p]
	if !ok || !o.n.same(n) {
		return node{}, ErrUnknown
	}
	o.n.UID = uid
	o.n.GID = gid
	f.objects[p] = o
	if f.failOwnerAt == f.ownerCalls && f.failOwnerAfter {
		return o.n, ErrUnknown
	}
	return o.n, nil
}

type fakeLock struct {
	fs   *fakeFS
	path string
}

func (l fakeLock) Close() error {
	delete(l.fs.heldLocks, l.path)
	l.fs.closedLocks = append(l.fs.closedLocks, l.path)
	if l.fs.closeErrorPath == l.path {
		return ErrUnknown
	}
	return nil
}
func (f *fakeFS) claimLock(p string, expected node) (io.Closer, error) {
	if f.onClaim != nil {
		f.onClaim(p)
	}
	n, e := f.inspect(p)
	if e != nil || !n.same(expected) || n.Kind != regular || n.UID != expected.UID || n.Mode != 0600 || n.Links != 1 || n.ACL {
		return nil, ErrUnknown
	}
	if p == f.busyLock || f.heldLocks[p] {
		return nil, ErrUnknown
	}
	if f.heldLocks == nil {
		f.heldLocks = map[string]bool{}
	}
	f.heldLocks[p] = true
	return fakeLock{f, p}, nil
}

type fakeRunner struct {
	states                                    map[string]serviceState
	events                                    []string
	logoutError, bootoutError                 bool
	onLogout                                  func()
	stateCalls                                int
	changeOnSecondRead                        bool
	pid                                       int
	pidError, drainError                      bool
	onDrain, onOffline                        func()
	offlineError, inspectorError              bool
	disabledValues                            map[string]bool
	gateEvents                                []bool
	gateError, gateQueryError, gateAfterError bool
	observeNoPID, observeStarting             bool
	onGate                                    func(bool)
	onBootstrap                               func()
}

func (r *fakeRunner) state(_ context.Context, l layout, _ Target) (serviceState, error) {
	r.stateCalls++
	if r.changeOnSecondRead && r.stateCalls == 2 {
		return unknown, nil
	}
	return r.states[l.Label], nil
}
func (r *fakeRunner) bootstrap(_ context.Context, l layout) error {
	r.events = append(r.events, "bootstrap")
	if r.onBootstrap != nil {
		r.onBootstrap()
	}
	r.states[l.Label] = matching
	return nil
}
func (r *fakeRunner) bootout(_ context.Context, l layout) error {
	r.events = append(r.events, "bootout")
	if r.bootoutError {
		return ErrUnknown
	}
	r.states[l.Label] = absent
	return nil
}
func (r *fakeRunner) logout(_ context.Context, _ layout, _ Target) error {
	r.events = append(r.events, "logout")
	if r.onLogout != nil {
		r.onLogout()
	}
	if r.logoutError {
		return ErrUnknown
	}
	return nil
}
func (r *fakeRunner) offlineLogout(_ context.Context, _ layout, _ Target) error {
	r.events = append(r.events, "offline-logout")
	if r.onOffline != nil {
		r.onOffline()
	}
	if r.offlineError {
		return ErrUnknown
	}
	return nil
}
func (r *fakeRunner) enrollmentCheck(_ context.Context, _ layout, _ Target) error {
	r.events = append(r.events, "local-check")
	if r.inspectorError {
		return ErrUnknown
	}
	return nil
}
func (r *fakeRunner) controlledPID(_ context.Context, l layout, _ Target) (int, error) {
	if r.pidError || r.states[l.Label] != matching {
		return 0, ErrUnknown
	}
	return r.pid, nil
}
func (r *fakeRunner) waitExit(_ context.Context, pid int) error {
	r.events = append(r.events, "drain")
	if r.onDrain != nil {
		r.onDrain()
	}
	if r.drainError || pid != r.pid {
		return ErrUnknown
	}
	return nil
}
func fixture() (*Manager, *fakeFS, *fakeRunner, InstallOptions) {
	f := &fakeFS{objects: map[string]fakeObject{}}
	for _, p := range []string{"/", "/usr", "/usr/local", "/usr/local/lib", "/Library", "/Library/Application Support", "/Library/LaunchDaemons", "/approved"} {
		f.add(p, directory, 0, 0, 0755, nil)
	}
	b := []byte("synthetic-approved-program-not-executed")
	f.add("/approved/harmonia", regular, 0, 0, 0755, b)
	r := &fakeRunner{states: map[string]serviceState{}, pid: 431}
	m := &Manager{target: Target{UserName: "synthetic", UID: 501, GID: 20}, fs: f, runner: r}
	return m, f, r, InstallOptions{Binary: "/approved/harmonia", BinarySHA256: digest(b)}
}
func installed(t *testing.T) (*Manager, *fakeFS, *fakeRunner) {
	t.Helper()
	m, f, r, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if e := m.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	addKnownLocks(f, paths(m.target), m.target)
	r.events = nil
	f.removed = nil
	f.closedLocks = nil
	f.publishCalls = 0
	return m, f, r
}
func addKnownLocks(f *fakeFS, l layout, target Target) {
	f.add(l.State+"/vault.lock", regular, target.UID, target.GID, 0600, nil)
	f.add(l.State+"/ipc", directory, target.UID, target.GID, 0700, nil)
	f.add(l.State+"/ipc/ipc.lock", regular, target.UID, target.GID, 0600, nil)
}
func requireRetained(t *testing.T, f *fakeFS, l layout) {
	t.Helper()
	for _, p := range []string{l.Binary, l.Plist, l.Receipt, l.State} {
		if _, ok := f.objects[p]; !ok {
			t.Fatalf("失败删除了 %s", p)
		}
	}
}

func TestInstallDoesNotStartOrGrantTrust(t *testing.T) {
	m, f, r, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if len(r.events) != 0 {
		t.Fatal("安装执行了服务操作")
	}
	l := paths(m.target)
	if _, ok := f.objects[l.State+"/machine-key.v1"]; ok {
		t.Fatal("安装器建立了凭据")
	}
	if n := f.objects[l.State].n; n.UID != 501 || n.GID != 20 || n.Mode != 0700 {
		t.Fatal(n)
	}
	if _, e := m.verify(); e != nil {
		t.Fatal(e)
	}
}
func TestInstallRejectsOldObjectsBeforeMutation(t *testing.T) {
	for _, which := range []string{"program", "state", "plist", "job"} {
		t.Run(which, func(t *testing.T) {
			m, f, r, o := fixture()
			l := paths(m.target)
			switch which {
			case "program":
				f.add(l.Program, other, 501, 20, 0777, nil)
			case "state":
				f.add(l.State, directory, 501, 20, 0700, nil)
			case "plist":
				f.add(l.Plist, regular, 0, 0, 0644, []byte("unknown"))
			case "job":
				r.states[l.Label] = unknown
			}
			before := len(f.objects)
			if e := m.Install(context.Background(), o); e == nil {
				t.Fatal("接受已有对象")
			}
			if len(f.objects) != before || len(f.removed) != 0 {
				t.Fatal("冲突产生了修改")
			}
		})
	}
}
func TestInstallRejectsUnsafeAncestorsAndSource(t *testing.T) {
	for _, which := range []string{"ancestorWrite", "ancestorACL", "ancestorOwner", "sourceLink", "sourceACL", "sourceOwner", "sourceSymlink", "digest"} {
		t.Run(which, func(t *testing.T) {
			m, f, _, o := fixture()
			p := "/approved/harmonia"
			if which == "ancestorWrite" || which == "ancestorACL" || which == "ancestorOwner" {
				p = "/Library/Application Support"
			}
			obj := f.objects[p]
			switch which {
			case "ancestorWrite":
				obj.n.Mode = 0775
			case "ancestorACL", "sourceACL":
				obj.n.ACL = true
			case "ancestorOwner", "sourceOwner":
				obj.n.UID = 501
			case "sourceLink":
				obj.n.Links = 2
			case "sourceSymlink":
				obj.n.Kind = other
			case "digest":
				o.BinarySHA256 = digest([]byte("different"))
			}
			f.objects[p] = obj
			before := len(f.objects)
			if e := m.Install(context.Background(), o); e == nil {
				t.Fatal("接受不安全输入")
			}
			if len(f.objects) != before || len(f.removed) != 0 {
				t.Fatal("预检失败后发生写入")
			}
		})
	}
}
func TestFailedInstallRollsBackOnlyNewObjects(t *testing.T) {
	m, f, _, o := fixture()
	l := paths(m.target)
	f.failWrite = l.Receipt
	before := len(f.objects)
	if e := m.Install(context.Background(), o); e == nil {
		t.Fatal("未注入失败")
	}
	if len(f.objects) != before+4 {
		t.Fatalf("回滚仅保留两个共享父目录、永久协调锁与禁启动权属: %d 原来%d", len(f.objects), before)
	}
	if _, ok := f.objects["/approved/harmonia"]; !ok {
		t.Fatal("删除了输入程序")
	}
	if _, ok := f.objects["/usr/local/lib"]; !ok {
		t.Fatal("删除了已有父目录")
	}
}
func TestRollbackDoesNotDeleteReplacedInode(t *testing.T) {
	m, f, _, _ := fixture()
	n := f.add("/new", directory, 0, 0, 0755, nil)
	f.add("/new", directory, 0, 0, 0755, nil)
	if e := m.rollback([]created{{"/new", n}}); e == nil {
		t.Fatal("换 inode 未拒绝")
	}
	if _, ok := f.objects["/new"]; !ok {
		t.Fatal("删除了替换对象")
	}
}

func TestLateUnknownServicePreservesMaterialsAndDoesNotBootout(t *testing.T) {
	m, f, r, o := fixture()
	f.onCommit = func(p string) {
		if p == paths(m.target).Plist {
			r.states[paths(m.target).Label] = unknown
		}
	}
	if e := m.Install(context.Background(), o); !errors.Is(e, ErrUnknown) {
		t.Fatal("结果不明未区分", e)
	}
	requireRetained(t, f, paths(m.target))
	if len(r.events) != 0 || len(f.removed) != 0 {
		t.Fatal("未知服务被卸载或删除材料")
	}
}

func TestSourceAndDestinationAncestorRoles(t *testing.T) {
	for _, which := range []string{"sourceUserOwned", "sourceWritable", "sourceACL", "destinationRootPrivate", "destinationExecuteOnly"} {
		t.Run(which, func(t *testing.T) {
			m, f, _, o := fixture()
			p := "/approved"
			if which == "destinationRootPrivate" || which == "destinationExecuteOnly" {
				p = "/Library/Application Support"
			}
			x := f.objects[p]
			switch which {
			case "sourceUserOwned":
				x.n.UID = 501
			case "sourceWritable":
				x.n.Mode = 0777
			case "sourceACL":
				x.n.ACL = true
			case "destinationRootPrivate":
				x.n.Mode = 0700
			case "destinationExecuteOnly":
				x.n.Mode = 0711
			}
			f.objects[p] = x
			before := len(f.objects)
			if e := m.Install(context.Background(), o); e == nil {
				t.Fatal("拒绝权限角色错误前没有失败")
			}
			if len(f.objects) != before || len(f.removed) != 0 {
				t.Fatal("祖先预检失败仍发生写入")
			}
		})
	}
	// 来源可仅 root 读取；复制后目标通过新的固定可达目录使用，不能要求来源公开。
	m, f, _, o := fixture()
	x := f.objects["/approved"]
	x.n.Mode = 0700
	f.objects["/approved"] = x
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal("root 私有输入被错误要求公开", e)
	}
}

func TestMatchedPrimaryGroupDoesNotFallBackToOthers(t *testing.T) {
	target := Target{UserName: "synthetic", UID: 501, GID: 20}
	for _, mode := range []uint32{0705, 0715} {
		if readableByTarget(node{UID: 0, GID: 20, Mode: mode}, target) {
			t.Fatalf("匹配主GID错误fallback others: %o", mode)
		}
	}
	if !readableByTarget(node{UID: 0, GID: 20, Mode: 0750}, target) {
		t.Fatal("匹配主GID的RX应可用")
	}
}
func TestTwoUIDLayoutsDoNotShareState(t *testing.T) {
	m, f, r, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	other := &Manager{target: Target{UserName: "synthetic2", UID: 502, GID: 20}, fs: f, runner: r}
	if e := other.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if paths(m.target).State == paths(other.target).State || paths(m.target).Label == paths(other.target).Label {
		t.Fatal("范围未隔离")
	}
	f.objects[paths(m.target).Binary] = fakeObject{n: f.objects[paths(m.target).Binary].n, data: []byte("tampered")}
	if e := m.Start(context.Background()); e == nil {
		t.Fatal("坏摘要仍启动")
	}
	if e := other.Start(context.Background()); e != nil {
		t.Fatal("另一用户被影响", e)
	}
}
func TestUninstallLogsOutBeforeBootoutAndDeletion(t *testing.T) {
	m, f, r := installed(t)
	l := paths(m.target)
	f.add(l.State+"/state.v1.enc", regular, 501, 20, 0600, []byte("synthetic-encrypted-state"))
	if e := m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(r.events) != 4 || r.events[0] != "logout" || r.events[1] != "bootout" || r.events[2] != "drain" || r.events[3] != "offline-logout" {
		t.Fatal(r.events)
	}
	for _, p := range []string{l.Program, l.State, l.Plist} {
		if _, ok := f.objects[p]; ok {
			t.Fatal("未删除本范围", p)
		}
	}
	if _, ok := f.objects["/usr/local/lib/harmonia"]; !ok {
		t.Fatal("删除了共享父目录")
	}
}
func TestUninstallUnknownEntriesStopBeforeLogout(t *testing.T) {
	for _, which := range []string{"program", "state", "ipc", "symlink", "hardlink"} {
		t.Run(which, func(t *testing.T) {
			m, f, r := installed(t)
			l := paths(m.target)
			switch which {
			case "program":
				f.add(l.Program+"/user-file", regular, 0, 0, 0644, nil)
			case "state":
				f.add(l.State+"/user-file", regular, 501, 20, 0600, nil)
			case "ipc":
				f.add(l.State+"/ipc", directory, 501, 20, 0700, nil)
				f.add(l.State+"/ipc/private", regular, 501, 20, 0600, nil)
			case "symlink":
				f.add(l.State+"/state.v1.enc", other, 501, 20, 0600, nil)
			case "hardlink":
				n := f.add(l.State+"/state.v1.enc", regular, 501, 20, 0600, nil)
				n.Links = 2
				f.objects[l.State+"/state.v1.enc"] = fakeObject{n: n}
			}
			if e := m.Uninstall(context.Background()); e == nil {
				t.Fatal("未知资料未阻止")
			}
			if len(r.events) != 0 || len(f.removed) != 0 {
				t.Fatal("未知范围已执行清理")
			}
			requireRetained(t, f, l)
		})
	}
}
func TestLogoutOrBootoutFailurePreservesFiles(t *testing.T) {
	for _, which := range []string{"logout", "bootout"} {
		t.Run(which, func(t *testing.T) {
			m, f, r := installed(t)
			r.logoutError = which == "logout"
			r.bootoutError = which == "bootout"
			if e := m.Uninstall(context.Background()); e == nil {
				t.Fatal("失败没返回")
			}
			requireRetained(t, f, paths(m.target))
			if len(f.removed) != 0 {
				t.Fatal("失败仍删除")
			}
			if which == "logout" && len(r.events) != 1 {
				t.Fatal("注销失败还停服务")
			}
		})
	}
}
func TestUnknownIPCAppearingDuringFreezeDeletesNothing(t *testing.T) {
	m, f, r := installed(t)
	l := paths(m.target)
	f.add(l.State+"/environment.sh", regular, 501, 20, 0600, nil)
	f.add(l.State+"/ipc", directory, 501, 20, 0700, nil)
	f.add(l.State+"/ipc/ipc.lock", regular, 501, 20, 0600, nil)
	f.onOwner = func(p string) {
		if p == l.State+"/ipc" {
			f.onOwner = nil
			f.add(p+"/new-private-file", regular, 501, 20, 0600, nil)
		}
	}
	if e := m.Uninstall(context.Background()); e == nil {
		t.Fatal("未知资料未阻止")
	}
	if len(f.removed) != 0 {
		t.Fatal("完整复检前删除了数据", f.removed)
	}
	if len(r.events) != 3 {
		t.Fatal(r.events)
	}
	requireRetained(t, f, l)
}
func TestPublicCARejectsNonCertificateData(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("garbage"), []byte("-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----")} {
		if publicCA(b) {
			t.Fatal("接受非公 CA")
		}
	}
}

func TestAccountNameUIDAndPrimaryGIDMustAllMatch(t *testing.T) {
	target := Target{UserName: "synthetic", UID: 501, GID: 20}
	good := identity{"synthetic", "501", "20"}
	if !matchingIdentity(target, good, good) {
		t.Fatal("正确身份未匹配")
	}
	for _, bad := range []identity{{"other", "501", "20"}, {"synthetic", "502", "20"}, {"synthetic", "501", "21"}} {
		if matchingIdentity(target, bad, good) || matchingIdentity(target, good, bad) {
			t.Fatal("单侧错误身份未拒绝")
		}
	}
	if validateTarget(Target{UserName: "root", UID: 0, GID: 0}) == nil || validateTarget(Target{UserName: "-option", UID: 501, GID: 20}) == nil {
		t.Fatal("危险身份未拒绝")
	}
}
func TestOptionalCAIsCopiedAndBoundToRootReceipt(t *testing.T) {
	m, f, r, o := fixture()
	// 明确合成固定种子，仅生成本测试公证书，不读取或记录任何用户私钥。
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	c := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(nil, c, c, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.add("/approved/ca.pem", regular, 0, 0, 0644, b)
	o.CAFile = "/approved/ca.pem"
	if e = m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	receipt, e := m.verify()
	if e != nil || receipt.CASHA256 != digest(b) {
		t.Fatal("CA 未绑定", e)
	}
	l := paths(m.target)
	if string(f.objects[l.CA].data) != string(b) {
		t.Fatal("CA 未复制原字节")
	}
	r.states[l.Label] = matching
	addKnownLocks(f, l, m.target)
	if e = m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, ok := f.objects[l.CA]; ok {
		t.Fatal("CA 未清理")
	}
	for _, bad := range [][]byte{append([]byte("garbage\n"), b...), append(append([]byte(nil), b...), []byte("extra data")...)} {
		if publicCA(bad) {
			t.Fatal("CA 接受非证书前后缀")
		}
	}
}

func TestStopWaitsForControlledPIDExit(t *testing.T) {
	m, f, r := installed(t)
	if e := m.Stop(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(r.events) != 2 || r.events[0] != "bootout" || r.events[1] != "drain" {
		t.Fatal(r.events)
	}
	requireRetained(t, f, paths(m.target))
	if len(f.removed) != 0 {
		t.Fatal("停止删除了文件")
	}
}
func TestUnknownOrStartingPIDDoesNotLogOutOrBootout(t *testing.T) {
	for _, which := range []string{"unknown", "zero", "one"} {
		t.Run(which, func(t *testing.T) {
			m, f, r := installed(t)
			switch which {
			case "unknown":
				r.pidError = true
			case "zero":
				r.pid = 0
			case "one":
				r.pid = 1
			case "absent":
				r.states[paths(m.target).Label] = absent
			}
			if e := m.Uninstall(context.Background()); !errors.Is(e, ErrUnknown) {
				t.Fatal(e)
			}
			if len(r.events) != 0 || len(f.removed) != 0 {
				t.Fatal("不明PID发生清理", r.events, f.removed)
			}
			requireRetained(t, f, paths(m.target))
		})
	}
}
func TestPIDChangesAfterLogoutAreRechecked(t *testing.T) {
	m, f, r := installed(t)
	r.onLogout = func() { r.pid = 432 }
	if e := m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(r.events) != 4 || len(f.removed) == 0 {
		t.Fatal("新受控PID未被等待")
	}
}
func TestStartingAfterLogoutPreservesMaterials(t *testing.T) {
	m, f, r := installed(t)
	r.onLogout = func() { r.pid = 0 }
	if e := m.Uninstall(context.Background()); !errors.Is(e, ErrUnknown) {
		t.Fatal(e)
	}
	if len(r.events) != 1 || len(f.removed) != 0 {
		t.Fatal("启动中job被停或删除")
	}
	requireRetained(t, f, paths(m.target))
}
func TestDrainFailureNeverFreezesOrDeletesState(t *testing.T) {
	for _, action := range []string{"stop", "uninstall"} {
		t.Run(action, func(t *testing.T) {
			m, f, r := installed(t)
			r.drainError = true
			f.onOwner = func(string) { t.Fatal("未证实退出就冻结目录") }
			var e error
			if action == "stop" {
				e = m.Stop(context.Background())
			} else {
				e = m.Uninstall(context.Background())
			}
			if !errors.Is(e, ErrUnknown) {
				t.Fatal(e)
			}
			requireRetained(t, f, paths(m.target))
			if len(f.removed) != 0 {
				t.Fatal("超时/复用PID导致删除")
			}
		})
	}
}
func TestUninstallHoldsBothOwnerLocksUntilLastDeletion(t *testing.T) {
	m, f, r := installed(t)
	l := paths(m.target)
	f.onClaim = func(p string) {
		if p == l.Control {
			return
		}
		if f.objects[l.State].n.UID != 0 || f.objects[l.State+"/ipc"].n.UID != 0 {
			t.Fatal("冻结前打开锁")
		}
		if len(r.events) < 3 || r.events[2] != "drain" {
			t.Fatal("退出前打开锁", r.events)
		}
	}
	f.beforeRemove = func(string) {
		if !f.heldLocks[l.State+"/vault.lock"] || !f.heldLocks[l.State+"/ipc/ipc.lock"] {
			t.Fatal("删除时未同时持有两锁")
		}
	}
	if e := m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(f.heldLocks) != 0 || len(f.closedLocks) != 5 {
		t.Fatal("成功后锁FD未关闭")
	}
}
func TestMissingOrBusyOwnerLocksPreserveEveryFile(t *testing.T) {
	for _, which := range []string{"missingVault", "missingIPC", "busyVault", "busyIPC"} {
		t.Run(which, func(t *testing.T) {
			m, f, _ := installed(t)
			l := paths(m.target)
			switch which {
			case "missingVault":
				delete(f.objects, l.State+"/vault.lock")
			case "missingIPC":
				delete(f.objects, l.State+"/ipc/ipc.lock")
			case "busyVault":
				f.busyLock = l.State + "/vault.lock"
			case "busyIPC":
				f.busyLock = l.State + "/ipc/ipc.lock"
			}
			if e := m.Uninstall(context.Background()); !errors.Is(e, ErrUnknown) {
				t.Fatal(e)
			}
			if len(f.removed) != 0 || len(f.heldLocks) != 0 {
				t.Fatal("未知所有者删除了材料或泄漏锁FD")
			}
			requireRetained(t, f, l)
			for _, p := range []string{l.State, l.State + "/ipc"} {
				if f.objects[p].n.UID != 501 || f.objects[p].n.GID != 20 {
					t.Fatal("失败后范围仍被root占有", p)
				}
			}
			if which == "busyIPC" && len(f.closedLocks) != 2 {
				t.Fatal("第二锁忙时没有释放首锁")
			}
		})
	}
}
func TestLockReplacedAfterSnapshotPreservesFiles(t *testing.T) {
	m, f, _ := installed(t)
	l := paths(m.target)
	f.onClaim = func(p string) {
		if p == l.State+"/ipc/ipc.lock" {
			f.add(p, regular, 501, 20, 0600, nil)
		}
	}
	if e := m.Uninstall(context.Background()); !errors.Is(e, ErrUnknown) {
		t.Fatal(e)
	}
	if len(f.removed) != 0 || len(f.heldLocks) != 0 {
		t.Fatal("换inode后删除了材料或泄漏锁")
	}
	requireRetained(t, f, l)
}

// 模型明确分离 unlink 的内存可见性与父目录同步；只有成功同步才能丢弃崩溃可恢复项。
func (f *fakeFS) durableAbsence(p string) error {
	f.absenceCalls++
	if _, ok := f.objects[p]; ok {
		return ErrUnknown
	}
	if f.failAbsenceSync {
		return ErrUnknown
	}
	delete(f.volatileRemovals, p)
	if f.failAbsenceClose {
		return ErrUnknown
	}
	return nil
}
func (f *fakeFS) crashUnsyncedUnlinks() {
	for p, o := range f.volatileRemovals {
		f.objects[p] = o
	}
	f.volatileRemovals = map[string]fakeObject{}
}
