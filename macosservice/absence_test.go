package macosservice

import (
	"context"
	"encoding/json"
	"testing"
)

func volatileInterruptedCleanup(t *testing.T) (*Manager, *fakeFS, journal) {
	t.Helper()
	m, f, _ := stoppedInstallation(t, true)
	f.volatileRemovals = map[string]fakeObject{}
	f.failRemoveAt, f.failRemoveAfter = 1, true
	if err := m.Uninstall(context.Background()); err == nil {
		t.Fatal("没有覆盖unlink成功后父目录同步失败")
	}
	f.failRemoveAt = 0
	j, _, err := m.loadJournal()
	if err != nil || j.Phase != "cleanup-authorized" || j.Next != 0 || len(f.volatileRemovals) != 1 {
		t.Fatal("没有留下精确持久cursor与volatile删除", j, err)
	}
	return m, f, j
}
func TestV6MissingCurrentFsyncFailureNeverAdvancesAndCrashCanRestore(t *testing.T) {
	m, f, before := volatileInterruptedCleanup(t)
	f.failAbsenceSync = true
	if err := m.Uninstall(context.Background()); err == nil {
		t.Fatal("把尚未持久的缺失当成可推进cursor")
	}
	after, _, err := m.loadJournal()
	if err != nil || after.Next != before.Next || len(f.volatileRemovals) != 1 {
		t.Fatal("同步失败仍推进持久cursor", after, err)
	}
	f.crashUnsyncedUnlinks()
	p, _ := m.itemPath(before.Plan[0])
	if _, err := f.inspect(p); err != nil {
		t.Fatal("模型没有在崩溃后恢复未同步unlink", err)
	}
	f.failAbsenceSync = false
	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatal("同一原cursor恢复失败", err)
	}
	requireRemovedInstallation(t, m, f)
}
func TestV6MissingCurrentCloseFailureDoesNotAdvance(t *testing.T) {
	m, f, before := volatileInterruptedCleanup(t)
	f.failAbsenceClose = true
	if err := m.Uninstall(context.Background()); err == nil {
		t.Fatal("缺失父FD Close失败仍成功")
	}
	after, _, err := m.loadJournal()
	if err != nil || after.Next != before.Next {
		t.Fatal("Close失败仍推进cursor", after, err)
	}
	if len(f.volatileRemovals) != 0 {
		t.Fatal("模型把已完成fsync说成未同步")
	}
	f.failAbsenceClose = false
	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRemovedInstallation(t, m, f)
}
func TestV6MissingCurrentSuccessfulSyncPrecedesNewCursor(t *testing.T) {
	m, f, before := volatileInterruptedCleanup(t)
	seen := false
	f.onPublish = func(_ string, b []byte) {
		var next journal
		if json.Unmarshal(b, &next) == nil && next.Phase == "cleanup-authorized" && next.Next == before.Next+1 {
			seen = true
			if len(f.volatileRemovals) != 0 || f.absenceCalls == 0 {
				t.Fatal("尚未同步缺失就写新cursor")
			}
		}
	}
	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("没有观测到新cursor发布")
	}
	requireRemovedInstallation(t, m, f)
}
func TestV6FinalJournalRemoveCloseFailureCannotClaimSuccess(t *testing.T) {
	m, f, _ := stoppedInstallation(t, true)
	f.removeCloseErrorPath = paths(m.target).Journal
	if err := m.Uninstall(context.Background()); err == nil {
		t.Fatal("最后record父FD Close失败仍成功")
	}
	f.removeCloseErrorPath = ""
	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatal("removed-disabled权威与同父缺失同步不能恢复", err)
	}
	requireRemovedInstallation(t, m, f)
}
