package platform

import (
	"context"
	"errors"
	"github.com/harmonia-vault/core-go/localstate"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type retryCommitStore struct {
	state         localstate.State
	saves, failAt int
}

func (s *retryCommitStore) Load() (localstate.State, error) { return s.state, nil }
func (s *retryCommitStore) Save(v localstate.State) error {
	s.saves++
	if s.saves == s.failAt {
		return errors.New("synthetic final commit failure")
	}
	s.state = v
	return nil
}
func TestWindowsReleaseKeepsTypedOriginalUntilEngineCommit(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	sid := "S-1-5-21-111-222-333-1001"
	original := RegistryValue{Value: "%SYNTHETIC_ROOT%", Expand: true}
	registry := &MemoryUserStore{SID: sid, Values: map[string]RegistryValue{"TOKEN": original, "UNRELATED": {Value: "keep"}}}
	directory := t.TempDir()
	if e := os.Chmod(directory, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(directory, "originals.json")
	provider, e := NewPersistentWindowsProvider(sid, registry, path)
	if e != nil {
		t.Fatal(e)
	}
	store := &retryCommitStore{state: localstate.EmptyState()}
	engine, e := localstate.New(store)
	if e != nil {
		t.Fatal(e)
	}
	if e = engine.EnableSyntheticFixtures(); e != nil {
		t.Fatal(e)
	}
	cloud := localstate.CloudSnapshot{AccountID: "synthetic-account", AccountGeneration: 1, Sequence: 1, Environments: map[string]localstate.Environment{"synthetic-env": {ID: "synthetic-env", KeyVersion: 1, GrantGeneration: 1, Role: localstate.ReadWrite, Values: map[string]string{"TOKEN": "synthetic-cloud"}}}}
	for _, e = range []error{engine.AcceptSnapshot(cloud, now), engine.Activate("synthetic-env", 1, now), engine.Reconcile(ctx, provider, now), engine.Deactivate("synthetic-env")} {
		if e != nil {
			t.Fatal(e)
		}
	}
	store.failAt = store.saves + 2
	if e = engine.Reconcile(ctx, provider, now); e == nil {
		t.Fatal("未触发engine最终提交失败")
	}
	if registry.Values["TOKEN"] != original {
		t.Fatal("真实恢复未执行")
	}
	registry.Values["TOKEN"] = RegistryValue{Value: "synthetic-external-after-failure"}
	provider, e = NewPersistentWindowsProvider(sid, registry, path)
	if e != nil {
		t.Fatal(e)
	}
	if e = engine.Reconcile(ctx, provider, now); e != nil {
		t.Fatal(e)
	}
	if registry.Values["TOKEN"] != original || len(engine.State().Originals) != 0 {
		t.Fatal("失败重试采纳了新值或丢失原类型")
	}
	if e = provider.ValidateTrackedKeys(nil); e != nil {
		t.Fatal(e)
	}
	if e = provider.Finalize(ctx); e != nil {
		t.Fatal(e)
	}
	registry.Values["TOKEN"] = RegistryValue{Value: "synthetic-new-baseline"}
	for _, e = range []error{engine.Activate("synthetic-env", 1, now), engine.Reconcile(ctx, provider, now), engine.Deactivate("synthetic-env"), engine.Reconcile(ctx, provider, now)} {
		if e != nil {
			t.Fatal(e)
		}
	}
	if registry.Values["TOKEN"] != (RegistryValue{Value: "synthetic-new-baseline"}) || registry.Values["UNRELATED"].Value != "keep" {
		t.Fatal("二次接管使用旧原值或改变无关项")
	}
}
