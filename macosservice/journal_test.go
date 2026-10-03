package macosservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func stoppedInstallation(t *testing.T, ipc bool) (*Manager, *fakeFS, *fakeRunner) {
	t.Helper()
	m, f, r, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	l := paths(m.target)
	f.add(l.State+"/vault.lock", regular, m.target.UID, m.target.GID, 0600, nil)
	f.add(l.State+"/machine-key.v1", regular, m.target.UID, m.target.GID, 0600, []byte("synthetic-opaque-machine-key"))
	f.add(l.State+"/state.v1.enc", regular, m.target.UID, m.target.GID, 0600, []byte("synthetic-opaque-local-state"))
	for _, name := range []string{"device.v1.enc", "session.v1.enc", "trust.v1.enc", "writes.v1.enc", "recovery.dag.v1.enc"} {
		f.add(l.State+"/"+name, regular, m.target.UID, m.target.GID, 0600, []byte("synthetic-opaque-account-slot"))
	}
	if ipc {
		f.add(l.State+"/ipc", directory, m.target.UID, m.target.GID, 0700, nil)
		f.add(l.State+"/ipc/ipc.lock", regular, m.target.UID, m.target.GID, 0600, nil)
	}
	r.onOffline = func() {
		for p := range f.objects {
			if strings.HasPrefix(p, l.State+"/") && accountFile(strings.TrimPrefix(p, l.State+"/")) {
				delete(f.objects, p)
			}
		}
	}
	f.removed = nil
	f.closedLocks = nil
	f.removeCalls = 0
	f.ownerCalls = 0
	f.publishCalls = 0
	return m, f, r
}
func requireRemovedInstallation(t *testing.T, m *Manager, f *fakeFS) {
	t.Helper()
	l := paths(m.target)
	for _, p := range []string{l.State, l.Program, l.Plist, l.Journal} {
		if _, ok := f.objects[p]; ok {
			t.Fatal("未清固定范围", p)
		}
	}
	if n, e := f.inspect(l.Control); e != nil || n.UID != 0 || n.Mode != 0600 {
		t.Fatal("永久协调锁被删/改变")
	}
	if len(f.heldLocks) != 0 {
		t.Fatal("返回后锁仍在")
	}
}
func TestV5StrictEmptyInstallationUninstallsWithoutLogoutOrCredentialCreation(t *testing.T) {
	m, f, r, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if e := m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(r.events) != 0 {
		t.Fatal("空安装执行了登录/退出/服务动作", r.events)
	}
	requireRemovedInstallation(t, m, f)
}
func TestV5StopThenUninstallAndNeverStartedEnrollment(t *testing.T) {
	for _, ipc := range []bool{false, true} {
		t.Run(fmt.Sprint(ipc), func(t *testing.T) {
			m, f, r := stoppedInstallation(t, ipc)
			if ipc {
				r.states[paths(m.target).Label] = matching
				if e := m.Stop(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			if e := m.Uninstall(context.Background()); e != nil {
				t.Fatal(e)
			}
			if strings.Join(r.events, ",") != (map[bool]string{false: "offline-logout", true: "bootout,drain,offline-logout"})[ipc] {
				t.Fatal("停止后意外启动/在线退出", r.events)
			}
			requireRemovedInstallation(t, m, f)
		})
	}
}
func TestV5JournalPublicationFailureBeforeAndAfterRenameRetriesEveryCursor(t *testing.T) {
	// 2阶段写+每项删后进度；两个方向都覆盖磁盘保留旧/新权威记录。
	for _, after := range []bool{false, true} {
		for at := 1; at <= 12; at++ {
			t.Run(fmt.Sprintf("after%v-write%d", after, at), func(t *testing.T) {
				m, f, r := stoppedInstallation(t, true)
				f.failPublishAt = at
				f.failPublishAfter = after
				if e := m.Uninstall(context.Background()); e == nil {
					t.Fatal("预期写/同步故障没有发生", at, f.publishCalls)
				}
				calls := len(r.events)
				f.failPublishAt = 0
				if e := m.Uninstall(context.Background()); e != nil {
					t.Fatal("已授权中断不能重试", e)
				}
				if calls > 0 && strings.Count(strings.Join(r.events, ","), "offline-logout") > 2 {
					t.Fatal("清理阶段重启了业务退出")
				}
				requireRemovedInstallation(t, m, f)
			})
		}
	}
}
func TestV5DeleteFailureBeforeAndAfterUnlinkRetriesEveryBoundary(t *testing.T) {
	for _, after := range []bool{false, true} {
		for at := 1; at <= 11; at++ {
			t.Run(fmt.Sprintf("after%v-delete%d", after, at), func(t *testing.T) {
				m, f, r := stoppedInstallation(t, true)
				f.failRemoveAt = at
				f.failRemoveAfter = after
				if e := m.Uninstall(context.Background()); e == nil {
					t.Fatal("预期删除/目录同步故障没有发生", at, f.removeCalls)
				}
				f.failRemoveAt = 0
				if e := m.Uninstall(context.Background()); e != nil {
					t.Fatal("精确中断及永久removed权威不能续清理", e)
				}
				if strings.Join(r.events, ",") != "offline-logout" {
					t.Fatal("清理阶段又退出/重启了业务", r.events)
				}
				requireRemovedInstallation(t, m, f)
			})
		}
	}
}
func TestV5PreparingOwnerMutationCrashRestartsWithExactRecordedDirectories(t *testing.T) {
	for _, after := range []bool{false, true} {
		for at := 1; at <= 6; at++ {
			t.Run(fmt.Sprintf("after%v-owner%d", after, at), func(t *testing.T) {
				m, f, _ := stoppedInstallation(t, true)
				f.failOwnerAt = at
				f.failOwnerAfter = after
				if e := m.Uninstall(context.Background()); e == nil {
					t.Fatal("预期owner故障没有发生")
				}
				f.failOwnerAt = 0
				if e := m.Uninstall(context.Background()); e != nil {
					t.Fatal("准备阶段无法按inode恢复", e)
				}
				requireRemovedInstallation(t, m, f)
			})
		}
	}
}
func TestV5OfflineFailureNewAccountAndSecondOwnerPreserveMaterials(t *testing.T) {
	for _, kind := range []string{"offline-failure", "new-account", "second-owner", "job-reappears", "ipc-missing-lock"} {
		t.Run(kind, func(t *testing.T) {
			m, f, r := stoppedInstallation(t, true)
			l := paths(m.target)
			switch kind {
			case "offline-failure":
				r.offlineError = true
			case "new-account":
				old := r.onOffline
				r.onOffline = func() {
					old()
					f.add(l.State+"/recovery.dag.v1.enc", regular, 501, 20, 0600, []byte("synthetic-new-account-journal"))
				}
			case "second-owner":
				old := r.onOffline
				r.onOffline = func() { old(); f.busyLock = l.State + "/vault.lock" }
			case "job-reappears":
				old := r.onOffline
				r.onOffline = func() { old(); r.states[l.Label] = matching }
			case "ipc-missing-lock":
				delete(f.objects, l.State+"/ipc/ipc.lock")
			}
			if e := m.Uninstall(context.Background()); e == nil {
				t.Fatal("未知/未完成状态仍清理")
			}
			requireRetained(t, f, l)
			if len(f.removed) != 0 {
				t.Fatal("未获清理授权已经删除", f.removed)
			}
		})
	}
}
func interruptedCleanup(t *testing.T) (*Manager, *fakeFS, *fakeRunner, journal) {
	t.Helper()
	m, f, r := stoppedInstallation(t, true)
	f.failPublishAt = 2
	f.failPublishAfter = true
	if e := m.Uninstall(context.Background()); e == nil {
		t.Fatal("没有中断授权写")
	}
	f.failPublishAt = 0
	j, _, e := m.loadJournal()
	if e != nil || j.Phase != "cleanup-authorized" {
		t.Fatal("没有保留完整授权记录", e)
	}
	return m, f, r, j
}
func TestV5OnlyCurrentAuthorizedItemMayBeMissing(t *testing.T) {
	for _, kind := range []string{"current", "future", "new-inode", "new-content", "unknown-child", "wrong-record", "bad-schema"} {
		t.Run(kind, func(t *testing.T) {
			m, f, _, j := interruptedCleanup(t)
			l := paths(m.target)
			x := j.Plan[0]
			p, _ := m.itemPath(x)
			switch kind {
			case "current":
				delete(f.objects, p)
			case "future":
				p, _ = m.itemPath(j.Plan[1])
				delete(f.objects, p)
			case "new-inode":
				o := f.objects[p]
				f.add(p, o.n.Kind, o.n.UID, o.n.GID, o.n.Mode, o.data)
			case "new-content":
				o := f.objects[p]
				o.data = []byte("synthetic-changed-content")
				f.objects[p] = o
			case "unknown-child":
				f.add(l.State+"/new-private-file", regular, 501, 20, 0600, nil)
			case "wrong-record":
				o := f.objects[l.Journal]
				j.Installation.UID = 502
				o.data, _ = json.Marshal(j)
				o.data = append(o.data, '\n')
				f.objects[l.Journal] = o
			case "bad-schema":
				o := f.objects[l.Journal]
				o.data = []byte("{\"version\":1}")
				f.objects[l.Journal] = o
			}
			before := len(f.removed)
			e := m.Uninstall(context.Background())
			if kind == "current" {
				if e != nil {
					t.Fatal("持久当前项不能幂等续清理", e)
				}
				requireRemovedInstallation(t, m, f)
			} else if e == nil || len(f.removed) != before {
				t.Fatal("未来缺失/未知对象获得了清理授权", e)
			}
		})
	}
}
func TestV5RootCoordinationAndJournalCloseDurabilityGate(t *testing.T) {
	for _, kind := range []string{"root-busy", "durable-error", "vault-close-error", "root-close-error", "start-pending", "stop-pending", "check-failure"} {
		t.Run(kind, func(t *testing.T) {
			m, f, r := stoppedInstallation(t, true)
			l := paths(m.target)
			switch kind {
			case "root-busy":
				f.busyLock = l.Control
			case "durable-error":
				_, f, _, _ = interruptedCleanup(t)
				m.fs = f
				f.durableError = true
			case "vault-close-error":
				f.closeErrorPath = l.State + "/vault.lock"
			case "root-close-error":
				f.closeErrorPath = l.Control
			case "start-pending", "stop-pending":
				rec, e := m.verify()
				if e != nil {
					t.Fatal(e)
				}
				j, e := m.prepareJournal(rec)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = m.saveJournal(j, nil); e != nil {
					t.Fatal(e)
				}
			case "check-failure":
				r.inspectorError = true
			}
			var e error
			if kind == "start-pending" || kind == "check-failure" {
				e = m.Start(context.Background())
			} else if kind == "stop-pending" {
				e = m.Stop(context.Background())
			} else {
				e = m.Uninstall(context.Background())
			}
			if kind == "stop-pending" {
				if e != nil {
					t.Fatal("合法事务允许正常停原job", e)
				}
				if _, _, e = m.loadJournal(); e != nil {
					t.Fatal("Stop删除事务", e)
				}
			} else if e == nil {
				t.Fatal("忙/同步/关闭/入网检查失败仍报告成功")
			}
			if kind != "root-close-error" && len(f.removed) != 0 {
				t.Fatal("门槛失败仍删除资料")
			}
		})
	}
}
func TestV5RandomCrashStageCannotGrantAuthorityOrBlockNewAttempt(t *testing.T) {
	m, f, r, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	l := paths(m.target)
	p := "/usr/local/lib/harmonia/.501.uninstall.json.stage.synthetic"
	f.add(p, regular, 0, 0, 0600, []byte("{truncated-not-authority"))
	if e := m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	if string(f.objects[p].data) != "{truncated-not-authority" || len(r.events) != 0 {
		t.Fatal("读取或删除了未引用stage")
	}
	if _, ok := f.objects[l.Journal]; ok {
		t.Fatal("有未清理record")
	}
}
func TestV5RollbackHoldsRootControlUntilLastNewObjectRemoval(t *testing.T) {
	m, f, _, o := fixture()
	l := paths(m.target)
	f.failWrite = l.Receipt
	f.beforeRemove = func(string) {
		if !f.heldLocks[l.Control] {
			t.Fatal("root协调锁提前释放导致回滚竞态")
		}
	}
	if e := m.Install(context.Background(), o); e == nil {
		t.Fatal("没有注入回滚故障")
	}
	if len(f.heldLocks) != 0 {
		t.Fatal("回滚后协调锁未关闭")
	}
}

func TestV5UnknownControlIdentityOrContentIsNeverRepaired(t *testing.T) {
	for _, kind := range []string{"uid", "gid", "mode", "hardlink", "acl", "content"} {
		t.Run(kind, func(t *testing.T) {
			m, f, r := stoppedInstallation(t, false)
			l := paths(m.target)
			o := f.objects[l.Control]
			switch kind {
			case "uid":
				o.n.UID = 501
			case "gid":
				o.n.GID = 20
			case "mode":
				o.n.Mode = 0644
			case "hardlink":
				o.n.Links = 2
			case "acl":
				o.n.ACL = true
			case "content":
				o.data = []byte("unknown-control-file")
			}
			f.objects[l.Control] = o
			if e := m.Uninstall(context.Background()); e == nil {
				t.Fatal("未知控制文件被使用/修复")
			}
			if len(r.events) != 0 || len(f.removed) != 0 || f.objects[l.Control].n != o.n || string(f.objects[l.Control].data) != string(o.data) {
				t.Fatal("拒绝前修改了控制文件/服务")
			}
		})
	}
}

// 安装认可的大小上限必须也能生成卸载计划，不能把合法较大程序留在不可卸载状态。
func TestV5AcceptedBinaryAbove64MiBUninstallsFromStrictEmptyState(t *testing.T) {
	m, f, _, o := fixture()
	data := bytes.Repeat([]byte{'a'}, 65<<20)
	defer clear(data)
	source := f.objects[o.Binary]
	source.data = data
	f.objects[o.Binary] = source
	o.BinarySHA256 = digest(data)
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal("公开上限内的来源安装失败", e)
	}
	if e := m.Uninstall(context.Background()); e != nil {
		t.Fatal("已认可的程序被更小的计划读取上限阻塞", e)
	}
	requireRemovedInstallation(t, m, f)
}
