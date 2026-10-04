package platform

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
)

var errSyntheticNotification = errors.New("synthetic notification unavailable")

type retryNotificationStore struct {
	MemoryUserStore
	fail   bool
	writes int
}

func (s *retryNotificationStore) Set(name string, value RegistryValue) error {
	s.writes++
	return s.MemoryUserStore.Set(name, value)
}
func (s *retryNotificationStore) Notify() error {
	s.Notifications++
	if s.fail {
		return errSyntheticNotification
	}
	return nil
}

func TestWindowsReconcileRetriesFailedNotificationWithoutRewritingValues(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	sid := "S-1-5-21-111-222-333-1001"
	registry := &retryNotificationStore{MemoryUserStore: MemoryUserStore{SID: sid, Values: map[string]RegistryValue{"TOKEN": {Value: "synthetic-original"}, "UNRELATED": {Value: "keep"}}}, fail: true}
	provider, err := NewWindowsProvider(sid, registry)
	if err != nil {
		t.Fatal(err)
	}
	store := &logoutEngineStore{state: localstate.EmptyState()}
	engine, err := localstate.New(store)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.EnableSyntheticFixtures(); err != nil {
		t.Fatal(err)
	}
	cloud := localstate.CloudSnapshot{AccountID: "synthetic-account", AccountGeneration: 1, Sequence: 1, Environments: map[string]localstate.Environment{"synthetic-env": {ID: "synthetic-env", KeyVersion: 1, GrantGeneration: 1, Role: localstate.ReadWrite, Values: map[string]string{"TOKEN": "synthetic-cloud"}}}}
	if err = engine.AcceptSnapshot(cloud, now); err != nil {
		t.Fatal(err)
	}
	if err = engine.Activate("synthetic-env", 1, now); err != nil {
		t.Fatal(err)
	}
	if err = engine.Reconcile(ctx, provider, now); !errors.Is(err, errSyntheticNotification) {
		t.Fatal("未保留首次通知失败", err)
	}
	if registry.Values["TOKEN"].Value != "synthetic-cloud" || registry.writes != 1 {
		t.Fatal("首次注册表写入未完成")
	}
	if err = engine.Reconcile(ctx, provider, now); !errors.Is(err, errSyntheticNotification) {
		t.Fatal("值已相同后吞掉通知失败", err)
	}
	if registry.Notifications != 2 || registry.writes != 1 || len(engine.State().Managed) != 0 {
		t.Fatal("重试重复写值或提前确认下发")
	}
	registry.fail = false
	if err = engine.Reconcile(ctx, provider, now); err != nil {
		t.Fatal(err)
	}
	if registry.Notifications != 3 || registry.writes != 1 || len(engine.State().Managed) != 1 {
		t.Fatal("通知成功后没有完成下发")
	}
	if err = engine.Reconcile(ctx, provider, now); err != nil {
		t.Fatal(err)
	}
	if registry.Notifications != 3 || registry.Values["UNRELATED"].Value != "keep" {
		t.Fatal("重复通知或改变无关变量")
	}
}

func TestSecureWindowsPendingNotificationSurvivesRestartAndRelease(t *testing.T) {
	vault, config := protectedVault(t)
	sid := "S-1-5-21-111-222-333-1001"
	if runtime.GOOS == "windows" {
		sid = config.UserID
	}
	registry := &retryNotificationStore{MemoryUserStore: MemoryUserStore{SID: sid, Values: map[string]RegistryValue{"TOKEN": {Value: "%SYNTHETIC_ROOT%", Expand: true}}}, fail: true}
	provider, err := NewSecureWindowsProvider(sid, registry, vault)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = provider.Apply(ctx, []localstate.Change{{Name: "TOKEN", Value: pointer("synthetic-cloud")}}); !errors.Is(err, errSyntheticNotification) {
		t.Fatal(err)
	}
	if err = vault.Close(); err != nil {
		t.Fatal(err)
	}
	vault, err = localkeys.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	provider, err = NewSecureWindowsProvider(sid, registry, vault)
	if err != nil {
		t.Fatal(err)
	}
	if err = provider.Apply(ctx, nil); !errors.Is(err, errSyntheticNotification) {
		t.Fatal("重启丢失待通知状态", err)
	}
	registry.fail = false
	if err = provider.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	registry.fail = true
	if err = provider.Apply(ctx, []localstate.Change{{Name: "TOKEN", Release: true}}); !errors.Is(err, errSyntheticNotification) {
		t.Fatal(err)
	}
	if registry.Values["TOKEN"] != (RegistryValue{Value: "%SYNTHETIC_ROOT%", Expand: true}) {
		t.Fatal("原值类型未恢复")
	}
	provider, err = NewSecureWindowsProvider(sid, registry, vault)
	if err != nil {
		t.Fatal(err)
	}
	if err = provider.Apply(ctx, nil); !errors.Is(err, errSyntheticNotification) {
		t.Fatal("释放后空原值表丢失待通知状态", err)
	}
	registry.fail = false
	if err = provider.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	provider, err = NewSecureWindowsProvider(sid, registry, vault)
	if err != nil {
		t.Fatal(err)
	}
	before := registry.Notifications
	if err = provider.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if registry.Notifications != before || registry.writes != 2 {
		t.Fatal("成功状态未持久保存或重试重复写入")
	}
}
