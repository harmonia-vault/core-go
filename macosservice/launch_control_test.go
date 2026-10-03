package macosservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestV6InstallAndStopRemainDisabledAcrossModelReboot(t *testing.T) {
	m, f, r, o := fixture()
	l := paths(m.target)
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	r.reboot(f, l)
	if r.states[l.Label] != absent || !r.disabledValues[l.Label] {
		t.Fatal("未Start安装随重启加载")
	}
	c, _, e := m.loadLaunch()
	if e != nil || c.Phase != "installed-disabled" {
		t.Fatal(c, e)
	}
	r.onGate = func(disabled bool) {
		if !disabled {
			c, _, e := m.loadLaunch()
			if e != nil || c.Phase != "start-authorized" {
				t.Fatal("尚未durable入网检查/Start意图就enable", c, e)
			}
		}
	}
	if e = m.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	r.onGate = nil
	if strings.Join(r.events, ",") != "local-check,bootstrap" {
		t.Fatal(r.events)
	}
	r.reboot(f, l)
	if r.states[l.Label] != matching {
		t.Fatal("明确Start不能重启加载")
	}
	if e = m.Stop(context.Background()); e != nil {
		t.Fatal(e)
	}
	r.reboot(f, l)
	if r.states[l.Label] != absent || !r.disabledValues[l.Label] {
		t.Fatal("Stop只bootout，没有持久禁启动")
	}
}
func TestV6UnknownExistingDisabledEntryIsNeverAdopted(t *testing.T) {
	for _, value := range []bool{false, true} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			m, f, r, o := fixture()
			l := paths(m.target)
			r.disabledValues = map[string]bool{l.Label: value}
			before := len(f.objects)
			if e := m.Install(context.Background(), o); e == nil {
				t.Fatal("未拥有条目被抢占")
			}
			if len(f.objects) != before || len(r.gateEvents) != 0 {
				t.Fatal("冲突前修改配置")
			}
		})
	}
}
func TestV6InstallCreationAndPublicationUnknownResumeExactAuthority(t *testing.T) {
	for _, point := range []string{"claim", "program-intent", "plist-intent", "complete-intent", "program-rename", "plist-rename"} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-after%v", point, after), func(t *testing.T) {
				m, f, r, o := fixture()
				l := paths(m.target)
				switch point {
				case "claim":
					f.failLaunchPublishAt = 1
				case "program-intent":
					f.failLaunchPublishAt = 2
				case "plist-intent":
					f.failLaunchPublishAt = 6
				case "complete-intent":
					f.failLaunchPublishAt = 7
				case "program-rename":
					f.failCommitAt = 3
				case "plist-rename":
					f.failCommitAt = 7
				}
				f.failLaunchPublishAfter = after
				f.failCommitAfter = after
				if e := m.Install(context.Background(), o); e == nil {
					t.Fatal("故障未生效")
				}
				prior, _, pe := m.loadLaunch()
				f.failLaunchPublishAt = 0
				f.failCommitAt = 0
				// 模型正常reboot只加载未被持久disabled的plist。
				r.reboot(f, l)
				if r.states[l.Label] != absent {
					t.Fatal("中断安装会在重启启动")
				}
				if e := m.Install(context.Background(), o); e != nil {
					t.Fatal("普通Install无法续同inode", e)
				}
				next, _, e := m.loadLaunch()
				if e != nil || next.Phase != "installed-disabled" {
					t.Fatal(next, e)
				}
				if pe == nil && prior.Installation.InstallationID != next.Installation.InstallationID {
					t.Fatal("恢复时替换原安装身份")
				}
				for i, x := range prior.Created {
					if next.Created[i] != x {
						t.Fatal("已记录inode被重建")
					}
				}
				if e = m.Uninstall(context.Background()); e != nil {
					t.Fatal(e)
				}
				requireRemovedInstallation(t, m, f)
			})
		}
	}
}
func TestV6UnreferencedTruncatedStageIsInertAndNeverDeleted(t *testing.T) {
	m, f, r, o := fixture()
	if e := m.ensureParents(); e != nil {
		t.Fatal(e)
	}
	p := "/usr/local/lib/harmonia/.harmonia.501.stage.ffffffffffffffffffffffffffffffff"
	n := f.add(p, regular, 0, 0, 0600, []byte("{truncated"))
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if e := m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.objects[p].n != n || string(f.objects[p].data) != "{truncated" || r.states[paths(m.target).Label] != absent {
		t.Fatal("未记录stage成了授权或被猜删")
	}
}
func TestV6PartialUninstallCancelsOnlyRecordedCreation(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			m, f, r, o := fixture()
			f.failCommitAt = 7
			f.failCommitAfter = after
			if e := m.Install(context.Background(), o); e == nil {
				t.Fatal("未中断plist提交")
			}
			f.failCommitAt = 0
			if e := m.Uninstall(context.Background()); e != nil {
				t.Fatal("部分普通Uninstall无法取消", e)
			}
			requireRemovedInstallation(t, m, f)
			if !r.disabledValues[paths(m.target).Label] {
				t.Fatal("部分取消未禁启动")
			}
		})
	}
}
func TestV6PartialCancelRejectsUnknownChildBeforeAnyDeletion(t *testing.T) {
	for _, scope := range []string{"state", "program"} {
		t.Run(scope, func(t *testing.T) {
			m, f, _, o := fixture()
			f.failCommitAt = 7
			if e := m.Install(context.Background(), o); e == nil {
				t.Fatal("没有部分安装")
			}
			f.failCommitAt = 0
			c, _, e := m.loadLaunch()
			if e != nil {
				t.Fatal(e)
			}
			var p string
			for _, x := range c.Created {
				if x.Scope == scope {
					p, _, _ = m.objectLocations(x)
				}
			}
			f.add(p+"/unknown", regular, m.target.UID, m.target.GID, 0600, []byte("synthetic-unknown"))
			if e = m.Uninstall(context.Background()); e == nil {
				t.Fatal("未知用户项没有闭锁")
			}
			if len(f.removed) != 0 {
				t.Fatal("集合核验前先删除可信项", f.removed)
			}
		})
	}
}
func TestV6PartialCancelCurrentMissingSyncFailureCannotAdvance(t *testing.T) {
	m, f, _, o := fixture()
	f.failCommitAt = 7
	if e := m.Install(context.Background(), o); e == nil {
		t.Fatal("缺少中断")
	}
	f.failCommitAt = 0
	f.volatileRemovals = map[string]fakeObject{}
	f.failRemoveAt = 1
	f.failRemoveAfter = true
	if e := m.Uninstall(context.Background()); e == nil {
		t.Fatal("缺少unlink故障")
	}
	f.failRemoveAt = 0
	c, _, e := m.loadLaunch()
	if e != nil || c.Phase != "cancelling-disabled" || c.Next != 0 {
		t.Fatal(c, e)
	}
	f.failAbsenceSync = true
	if e = m.Uninstall(context.Background()); e == nil {
		t.Fatal("缺失未同步仍成功")
	}
	next, _, e := m.loadLaunch()
	if e != nil || next.Next != 0 {
		t.Fatal(next, e)
	}
	f.failAbsenceSync = false
	f.crashUnsyncedUnlinks()
	if e = m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	requireRemovedInstallation(t, m, f)
}
func TestV6PendingUninstallStopsOwnedReappearedJobWithoutIPC(t *testing.T) {
	for _, phase := range []string{"preparing", "cleanup-authorized"} {
		for _, noPID := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-noPID%v", phase, noPID), func(t *testing.T) {
				m, f, r := stoppedInstallation(t, true)
				f.failPublishAt = map[string]int{"preparing": 1, "cleanup-authorized": 2}[phase]
				f.failPublishAfter = true
				if e := m.Uninstall(context.Background()); e == nil {
					t.Fatal("缺少事务中断")
				}
				f.failPublishAt = 0
				j, _, e := m.loadJournal()
				if e != nil || j.Phase != phase {
					t.Fatal(j, e)
				}
				r.events = nil
				r.states[paths(m.target).Label] = matching
				r.observeNoPID = noPID
				if e = m.Uninstall(context.Background()); e != nil {
					t.Fatal("普通Uninstall无法恢复原job", e)
				}
				if strings.Contains(strings.Join(r.events, ","), "logout,bootout") {
					t.Fatal("冻结事务仍依赖IPC")
				}
				if !strings.HasPrefix(strings.Join(r.events, ","), "bootout") {
					t.Fatal(r.events)
				}
				requireRemovedInstallation(t, m, f)
			})
		}
	}
}
func TestV6PendingOwnedJobStartingOrUnknownOrOwnerBusyPreserves(t *testing.T) {
	for _, kind := range []string{"starting", "unknown", "noPID-busy"} {
		t.Run(kind, func(t *testing.T) {
			m, f, r, _ := interruptedCleanup(t)
			l := paths(m.target)
			r.events = nil
			r.states[l.Label] = matching
			switch kind {
			case "starting":
				r.observeStarting = true
			case "unknown":
				r.states[l.Label] = unknown
			case "noPID-busy":
				r.observeNoPID = true
				f.busyLock = l.State + "/vault.lock"
			}
			if e := m.Uninstall(context.Background()); e == nil {
				t.Fatal("不明原owner仍删除")
			}
			if len(f.removed) != 0 {
				t.Fatal(f.removed)
			}
			requireRetained(t, f, l)
		})
	}
}
func TestV6StartDurableAuthorizationAndGateUnknownAreRecoverable(t *testing.T) {
	m, f, r, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	r.gateAfterError = true
	if e := m.Start(context.Background()); e == nil {
		t.Fatal("enable回应不明仍成功")
	}
	c, _, e := m.loadLaunch()
	if e != nil || c.Phase != "installed-disabled" {
		t.Fatal(c, e)
	}
	r.gateAfterError = false
	r.reboot(f, paths(m.target))
	if r.states[paths(m.target).Label] != absent {
		t.Fatal("失败补偿未禁启动")
	}
	if e = m.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestV6LostStartAuthorizedWriteNeverEnablesBeforeConfirmedRetry(t *testing.T) {
	m, f, r, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	f.failLaunchPublishAt = f.launchPublishCalls + 1
	f.failLaunchPublishAfter = true
	if e := m.Start(context.Background()); e == nil {
		t.Fatal("授权记录回应不明仍启动")
	}
	if !r.disabledValues[paths(m.target).Label] {
		t.Fatal("没有确认本次记录就enable")
	}
	f.failLaunchPublishAt = 0
	if e := m.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestV6RemovedAuthoritySupportsSyncRetryAndFreshIdentity(t *testing.T) {
	m, f, r, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	old, _, e := m.loadLaunch()
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	f.failAbsenceClose = true
	if e = m.Uninstall(context.Background()); e == nil {
		t.Fatal("缺失Close失败仍报成功")
	}
	f.failAbsenceClose = false
	if e = m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	next, _, e := m.loadLaunch()
	if e != nil || next.Installation.InstallationID == old.Installation.InstallationID {
		t.Fatal("新装复用旧安装身份", e)
	}
	if !r.disabledValues[paths(m.target).Label] {
		t.Fatal("新装沿用了enabled")
	}
}
func TestV6AuthorityBadBindingNeverRepairsOrDeletes(t *testing.T) {
	for _, kind := range []string{"installation", "unknownfield", "owner", "nlink", "parent", "stage", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			m, f, r, o := fixture()
			if e := m.Install(context.Background(), o); e != nil {
				t.Fatal(e)
			}
			p := launchPath(paths(m.target))
			before := f.objects[p]
			obj := before
			var c launchControl
			json.Unmarshal(obj.data, &c)
			switch kind {
			case "installation":
				c.Installation.InstallationID = "bad"
			case "unknownfield":
				obj.data = []byte(`{"unexpected":true}`)
			case "owner":
				obj.n.UID = 501
			case "nlink":
				obj.n.Links = 2
			case "parent":
				c.Created[0].Parent.Inode++
			case "stage":
				c.Created[0].Stage = "../other"
			case "truncated":
				obj.data = []byte("{")
			}
			if kind == "installation" || kind == "parent" || kind == "stage" {
				b, _ := json.Marshal(c)
				obj.data = append(b, '\n')
			}
			f.objects[p] = obj
			gateCount := len(r.gateEvents)
			if e := m.Uninstall(context.Background()); e == nil {
				t.Fatal("坏权属没有闭锁")
			}
			if len(f.removed) != 0 || len(r.gateEvents) != gateCount || string(f.objects[p].data) != string(obj.data) {
				t.Fatal("未知record被修改")
			}
		})
	}
}
func TestV6ClaimOnlyCannotStopUnknownPartialService(t *testing.T) {
	m, f, r, o := fixture()
	f.failLaunchPublishAt = 1
	f.failLaunchPublishAfter = true
	if e := m.Install(context.Background(), o); e == nil {
		t.Fatal("没有claim中断")
	}
	f.failLaunchPublishAt = 0
	r.states[paths(m.target).Label] = matching
	if e := m.Uninstall(context.Background()); e == nil {
		t.Fatal("仅claim就当成已拥有job")
	}
	if len(r.events) != 0 {
		t.Fatal("停止未拥有的partialjob", r.events)
	}
}
func TestV6NoAuthorityCannotInventRemovedSuccess(t *testing.T) {
	m, f, _, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if e := m.Uninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	delete(f.objects, launchPath(paths(m.target)))
	if e := m.Uninstall(context.Background()); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("没有record仍自造成功", e)
	}
}
func TestV6FinalRemovedPublicationUnknownPreservesJournalForRetry(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			m, f, _, o := fixture()
			if e := m.Install(context.Background(), o); e != nil {
				t.Fatal(e)
			}
			f.failLaunchPublishAt = f.launchPublishCalls + 2 // uninstalling→最后removed，两者与journal游标独立。
			f.failLaunchPublishAfter = after
			if e := m.Uninstall(context.Background()); e == nil {
				t.Fatal("最终权属发布不明仍成功")
			}
			if _, _, e := m.loadJournal(); e != nil {
				t.Fatal("最终authority未确认先删journal", e)
			}
			f.failLaunchPublishAt = 0
			if e := m.Uninstall(context.Background()); e != nil {
				t.Fatal("普通Uninstall无法恢复最后阶段", e)
			}
			requireRemovedInstallation(t, m, f)
		})
	}
}
func TestV6StartAuthorizedLoadedJobRechecksEnrollmentBeforeEnable(t *testing.T) {
	m, f, r, o := fixture()
	if e := m.Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	c, n, e := m.loadLaunch()
	if e != nil {
		t.Fatal(e)
	}
	c.Phase = "start-authorized"
	if _, e = m.saveLaunch(c, &n); e != nil {
		t.Fatal(e)
	}
	r.states[paths(m.target).Label] = matching
	r.inspectorError = true
	before := len(r.gateEvents)
	if e = m.Start(context.Background()); e == nil {
		t.Fatal("回应不明后的Start仅据loaded运行就重新enable")
	}
	for _, enabled := range r.gateEvents[before:] {
		if !enabled {
			t.Fatal("重新核本地来源前enable")
		}
	}
	if strings.Join(r.events, ",") != "bootout,drain,local-check" {
		t.Fatal("没有正常停止并重新核来源", r.events)
	}
	if _, e = f.inspect(paths(m.target).Binary); e != nil {
		t.Fatal("失败删材料", e)
	}
}
