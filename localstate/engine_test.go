package localstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type memoryStore struct {
	mu     sync.Mutex
	state  State
	saves  int
	failAt int
}

func (m *memoryStore) Load() (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return clone(m.state), nil
}
func (m *memoryStore) Save(s State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saves++
	if m.failAt == m.saves {
		return errors.New("synthetic disk error")
	}
	m.state = clone(s)
	return nil
}

type memoryProvider struct {
	values    map[string]string
	snapshots [][]string
	changes   []Change
	failAfter int
}

func (p *memoryProvider) Snapshot(_ context.Context, keys []string) (map[string]string, error) {
	p.snapshots = append(p.snapshots, append([]string(nil), keys...))
	out := map[string]string{}
	for _, k := range keys {
		if v, ok := p.values[k]; ok {
			out[k] = v
		}
	}
	return out, nil
}
func (p *memoryProvider) Apply(_ context.Context, changes []Change) error {
	for i, c := range changes {
		if p.failAfter > 0 && i == p.failAfter {
			return errors.New("synthetic partial apply")
		}
		p.changes = append(p.changes, c)
		if c.Value == nil {
			delete(p.values, c.Name)
		} else {
			p.values[c.Name] = *c.Value
		}
	}
	return nil
}
func newTest(t *testing.T) (*Engine, *memoryStore, *memoryProvider) {
	t.Helper()
	store := &memoryStore{state: EmptyState()}
	e, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	p := &memoryProvider{values: map[string]string{"TOKEN": "original", "UNRELATED": "untouched"}}
	return e, store, p
}
func env(id string, values map[string]string) Environment {
	return Environment{ID: id, KeyVersion: 1, GrantGeneration: 1, Role: ReadWrite, Values: values}
}
func snapshot(seq uint64, envs ...Environment) CloudSnapshot {
	s := CloudSnapshot{AccountID: "synthetic-account", AccountGeneration: 1, Sequence: seq, Environments: map[string]Environment{}}
	for _, e := range envs {
		s.Environments[e.ID] = e
	}
	return s
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func reconcile(t *testing.T, e *Engine, p Provider, now time.Time) {
	t.Helper()
	must(t, e.Reconcile(context.Background(), p, now))
}
func TestPriorityOverrideRestorationAndUnrelated(t *testing.T) {
	e, _, p := newTest(t)
	must(t, e.AcceptSnapshot(snapshot(1, env("base", map[string]string{"TOKEN": "base", "BASE": "base-only"}), env("prod", map[string]string{"TOKEN": "prod", "PROD": "prod-only"})), testNow))
	must(t, e.Activate("base", 1, testNow))
	must(t, e.Activate("prod", 10, testNow))
	must(t, e.SetOverride("base", "TOKEN", "base-override", testNow))
	reconcile(t, e, p, testNow)
	if p.values["TOKEN"] != "prod" || p.values["BASE"] != "base-only" || p.values["PROD"] != "prod-only" {
		t.Fatal(p.values)
	}
	must(t, e.SetOverride("prod", "TOKEN", "local-prod", testNow))
	reconcile(t, e, p, testNow)
	if p.values["TOKEN"] != "local-prod" {
		t.Fatal(p.values)
	}
	// 纠正托管变量的直接修改，同时保留无关修改。
	p.values["TOKEN"] = "external"
	p.values["UNRELATED"] = "external-unrelated"
	reconcile(t, e, p, testNow)
	if p.values["TOKEN"] != "local-prod" {
		t.Fatal("managed edit not corrected")
	}
	must(t, e.Deactivate("prod"))
	reconcile(t, e, p, testNow)
	if p.values["TOKEN"] != "base-override" {
		t.Fatal(p.values)
	}
	if _, ok := p.values["PROD"]; ok {
		t.Fatal("tool-created key not removed")
	}
	must(t, e.Deactivate("base"))
	reconcile(t, e, p, testNow)
	want := map[string]string{"TOKEN": "original", "UNRELATED": "external-unrelated"}
	if !reflect.DeepEqual(p.values, want) {
		t.Fatalf("got %v, want %v", p.values, want)
	}
	if len(e.State().Originals) != 0 {
		t.Fatal("released originals retained")
	}
	for _, keys := range p.snapshots {
		for _, k := range keys {
			if k == "UNRELATED" {
				t.Fatal("unrelated environment was read")
			}
		}
	}
}
func TestTiePriorityUsesLaterActivation(t *testing.T) {
	e, _, p := newTest(t)
	must(t, e.AcceptSnapshot(snapshot(1, env("a", map[string]string{"TOKEN": "a"}), env("b", map[string]string{"TOKEN": "b"})), testNow))
	must(t, e.Activate("a", 5, testNow))
	must(t, e.Activate("b", 5, testNow))
	reconcile(t, e, p, testNow)
	if p.values["TOKEN"] != "b" {
		t.Fatal(p.values)
	}
}
func TestCloudDeletionRemovesOverrideAndDoesNotResurrect(t *testing.T) {
	e, _, p := newTest(t)
	must(t, e.AcceptSnapshot(snapshot(1, env("a", map[string]string{"TOKEN": "cloud"})), testNow))
	must(t, e.Activate("a", 1, testNow))
	must(t, e.SetOverride("a", "TOKEN", "local", testNow))
	reconcile(t, e, p, testNow)
	must(t, e.AcceptSnapshot(snapshot(2, env("a", map[string]string{})), testNow))
	reconcile(t, e, p, testNow)
	if p.values["TOKEN"] != "original" || len(e.State().Overrides["a"]) != 0 {
		t.Fatal(e.State())
	}
	must(t, e.AcceptSnapshot(snapshot(3, env("a", map[string]string{"TOKEN": "new"})), testNow))
	reconcile(t, e, p, testNow)
	if p.values["TOKEN"] != "new" {
		t.Fatal("stale override resurrected")
	}
}
func TestPausedKeepsValuesButRevocationRecomputes(t *testing.T) {
	e, _, p := newTest(t)
	must(t, e.AcceptSnapshot(snapshot(1, env("base", map[string]string{"TOKEN": "base", "BASE": "one"}), env("high", map[string]string{"TOKEN": "high", "EXTRA": "high"})), testNow))
	must(t, e.Activate("base", 1, testNow))
	must(t, e.Activate("high", 2, testNow))
	reconcile(t, e, p, testNow)
	must(t, e.SetPaused(true))
	p.values["BASE"] = "external-paused"
	p.values["TOKEN"] = "external-paused"
	reconcile(t, e, p, testNow)
	if p.values["TOKEN"] != "external-paused" {
		t.Fatal("pause corrected ordinary external edit")
	}
	must(t, e.AcceptSnapshot(snapshot(2, env("base", map[string]string{"TOKEN": "base", "BASE": "two"})), testNow))
	reconcile(t, e, p, testNow)
	if p.values["TOKEN"] != "base" {
		t.Fatal("paused revocation did not fall back")
	}
	if _, ok := p.values["EXTRA"]; ok {
		t.Fatal("revoked sole source retained")
	}
	if p.values["BASE"] != "external-paused" {
		t.Fatal("unaffected paused key corrected")
	}
	must(t, e.SetPaused(false))
	reconcile(t, e, p, testNow)
	if p.values["BASE"] != "two" {
		t.Fatal("resume did not converge")
	}
}
func TestOfflineExpiryClearsOverridesAndFallsBackWhilePaused(t *testing.T) {
	e, _, p := newTest(t)
	expiry := testNow.Add(time.Minute)
	high := env("high", map[string]string{"TOKEN": "high", "NEW": "temporary"})
	high.ExpiresAt = &expiry
	must(t, e.AcceptSnapshot(snapshot(1, env("base", map[string]string{"TOKEN": "base"}), high), testNow))
	must(t, e.Activate("base", 1, testNow))
	must(t, e.Activate("high", 2, testNow))
	must(t, e.SetOverride("high", "TOKEN", "local", testNow))
	reconcile(t, e, p, testNow)
	must(t, e.SetPaused(true))
	reconcile(t, e, p, expiry)
	if p.values["TOKEN"] != "base" {
		t.Fatal(p.values)
	}
	if _, ok := p.values["NEW"]; ok {
		t.Fatal("expired plaintext still active")
	}
	if _, ok := e.State().Cloud.Environments["high"]; ok {
		t.Fatal("expired cache retained")
	}
	if _, ok := e.State().Overrides["high"]; ok {
		t.Fatal("expired override retained")
	}
	if !errors.Is(e.SetOverride("high", "TOKEN", "x", expiry), ErrUnauthorized) {
		t.Fatal("expired override accepted")
	}
}
func TestCheckpointAndGeneration(t *testing.T) {
	e, _, p := newTest(t)
	first := snapshot(10, env("a", map[string]string{"TOKEN": "one"}))
	must(t, e.AcceptSnapshot(first, testNow))
	must(t, e.Activate("a", 1, testNow))
	reconcile(t, e, p, testNow)
	must(t, e.AcceptSnapshot(first, testNow))
	if !errors.Is(e.AcceptSnapshot(snapshot(9), testNow), ErrReplay) {
		t.Fatal("lower sequence accepted")
	}
	if !errors.Is(e.AcceptSnapshot(snapshot(10), testNow), ErrReplay) {
		t.Fatal("changed equal sequence accepted")
	}
	different := first
	different.AccountID = "other"
	if !errors.Is(e.AcceptSnapshot(different, testNow), ErrAccount) {
		t.Fatal("other account accepted")
	}
	next := snapshot(0)
	next.AccountGeneration = 2
	must(t, e.AcceptSnapshot(next, testNow))
	reconcile(t, e, p, testNow)
	if p.values["TOKEN"] != "original" || len(e.State().Active) != 0 {
		t.Fatal("old generation remained active")
	}
	if !errors.Is(e.AcceptSnapshot(first, testNow), ErrReplay) {
		t.Fatal("old generation accepted")
	}
}
func TestCallerCannotMutateAuthority(t *testing.T) {
	e, _, _ := newTest(t)
	input := snapshot(1, env("a", map[string]string{"TOKEN": "one"}))
	must(t, e.AcceptSnapshot(input, testNow))
	input.Environments["a"].Values["TOKEN"] = "caller"
	state := e.State()
	state.Cloud.Environments["a"].Values["TOKEN"] = "caller"
	if e.State().Cloud.Environments["a"].Values["TOKEN"] != "one" {
		t.Fatal("map alias bypassed engine")
	}
}
func TestPartialProviderFailureThenRestart(t *testing.T) {
	e, store, p := newTest(t)
	must(t, e.AcceptSnapshot(snapshot(1, env("a", map[string]string{"TOKEN": "cloud", "NEW": "new"})), testNow))
	must(t, e.Activate("a", 1, testNow))
	p.failAfter = 1
	if e.Reconcile(context.Background(), p, testNow) == nil {
		t.Fatal("partial apply should fail")
	}
	restarted, err := New(store)
	must(t, err)
	p.failAfter = 0
	reconcile(t, restarted, p, testNow)
	must(t, restarted.Logout())
	reconcile(t, restarted, p, testNow)
	if !reflect.DeepEqual(p.values, map[string]string{"TOKEN": "original", "UNRELATED": "untouched"}) {
		t.Fatal(p.values)
	}
}
func TestCrashAfterApplyBeforeCheckpointThenLogoutRestores(t *testing.T) {
	e, store, p := newTest(t)
	must(t, e.AcceptSnapshot(snapshot(1, env("a", map[string]string{"TOKEN": "cloud", "NEW": "new"})), testNow))
	must(t, e.Activate("a", 1, testNow))
	store.failAt = store.saves + 2
	if e.Reconcile(context.Background(), p, testNow) == nil {
		t.Fatal("final save failure expected")
	}
	if p.values["TOKEN"] != "cloud" {
		t.Fatal("fixture must have applied")
	}
	restarted, err := New(store)
	must(t, err)
	must(t, restarted.Logout())
	reconcile(t, restarted, p, testNow)
	if p.values["TOKEN"] != "original" {
		t.Fatal("first-takeover original lost on crash")
	}
	if _, ok := p.values["NEW"]; ok {
		t.Fatal("crashed tool-added key not removed")
	}
}
func TestSaveFailureDoesNotMutateCloud(t *testing.T) {
	e, store, _ := newTest(t)
	store.failAt = 1
	if e.AcceptSnapshot(snapshot(1, env("a", map[string]string{"TOKEN": "one"})), testNow) == nil {
		t.Fatal("save should fail")
	}
	if e.State().Cloud.AccountID != "" {
		t.Fatal("failed save mutated authority")
	}
}
func TestRejectInvalidNamesAndOverrides(t *testing.T) {
	e, _, _ := newTest(t)
	if e.AcceptSnapshot(snapshot(1, env("a", map[string]string{"BAD-NAME": "x"})), testNow) == nil {
		t.Fatal("invalid variable accepted")
	}
	must(t, e.AcceptSnapshot(snapshot(1, env("a", map[string]string{"GOOD": "x"})), testNow))
	if e.SetOverride("a", "MISSING", "x", testNow) == nil {
		t.Fatal("override manufactured deleted key")
	}
	if e.SetOverride("a", "GOOD", "nul\x00", testNow) == nil {
		t.Fatal("NUL accepted")
	}
}
func TestSelectedImportDoesNotUploadUnselected(t *testing.T) {
	selected, err := SelectImport(map[string]string{"SELECTED": "synthetic", "UNSELECTED": "private"}, []string{"SELECTED"})
	must(t, err)
	if !reflect.DeepEqual(selected, map[string]string{"SELECTED": "synthetic"}) {
		t.Fatal(selected)
	}
	if _, err = SelectImport(map[string]string{}, nil); err == nil {
		t.Fatal("implicit import allowed")
	}
}
func TestConcurrentEngineOperations(t *testing.T) {
	e, _, _ := newTest(t)
	must(t, e.AcceptSnapshot(snapshot(1, env("a", map[string]string{"TOKEN": "cloud"})), testNow))
	must(t, e.Activate("a", 1, testNow))
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() {
			for range 50 {
				_ = e.SetOverride("a", "TOKEN", "local", testNow)
				_ = e.State()
				_, _ = e.Effective(testNow)
			}
		})
	}
	wg.Wait()
}
func TestFileStoreLockPersistenceAndFileProvider(t *testing.T) {
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0700))
	statePath := filepath.Join(dir, "state.json")
	store, err := OpenFileStore(statePath)
	must(t, err)
	if duplicate, err := OpenFileStore(statePath); err == nil {
		_ = duplicate.Close()
		t.Fatal("concurrent process lock missing")
	}
	e, err := New(store)
	must(t, err)
	provider := &FileProvider{Path: filepath.Join(dir, "environment.json")}
	must(t, provider.Apply(context.Background(), []Change{{Name: "TOKEN", Value: ptr("original")}, {Name: "UNRELATED", Value: ptr("one")}}))
	must(t, e.AcceptSnapshot(snapshot(1, env("a", map[string]string{"TOKEN": "cloud"})), testNow))
	must(t, e.Activate("a", 1, testNow))
	reconcile(t, e, provider, testNow)
	must(t, store.Close())
	store, err = OpenFileStore(statePath)
	must(t, err)
	defer store.Close()
	e, err = New(store)
	must(t, err)
	must(t, provider.Apply(context.Background(), []Change{{Name: "UNRELATED", Value: ptr("external")}}))
	must(t, e.Logout())
	reconcile(t, e, provider, testNow)
	values, err := provider.Snapshot(context.Background(), []string{"TOKEN", "UNRELATED"})
	must(t, err)
	if values["TOKEN"] != "original" || values["UNRELATED"] != "external" {
		t.Fatal(values)
	}
	info, err := os.Stat(statePath)
	must(t, err)
	if err = privateFile(info); err != nil {
		t.Fatal(err)
	}
}
func TestStateRejectsSymlinkAndPublicCache(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Windows ACL policy is covered by platform runtime tests")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	must(t, os.WriteFile(target, []byte(`{}`), 0600))
	link := filepath.Join(dir, "state.json")
	must(t, os.Symlink(target, link))
	store, err := OpenFileStore(link)
	if err == nil {
		defer store.Close()
		if _, err = store.Load(); err == nil {
			t.Fatal("symlink cache accepted")
		}
	}
	unsafe := filepath.Join(dir, "public.json")
	must(t, os.WriteFile(unsafe, []byte(`{}`), 0644))
	if err = readJSON(unsafe, &map[string]string{}); err == nil {
		t.Fatal("public cache accepted")
	}
}
func ptr(s string) *string { return &s }

type unavailableProvider struct{}

func (unavailableProvider) Snapshot(context.Context, []string) (map[string]string, error) {
	return nil, errors.New("synthetic unavailable provider")
}
func (unavailableProvider) Apply(context.Context, []Change) error {
	return errors.New("synthetic unavailable provider")
}
func TestExpiryAndLogoutClearManagedPlaintextBeforeProviderRecovery(t *testing.T) {
	for _, logout := range []bool{false, true} {
		t.Run(map[bool]string{false: "expiry", true: "logout"}[logout], func(t *testing.T) {
			e, store, p := newTest(t)
			expiry := testNow.Add(time.Minute)
			temporary := env("temporary", map[string]string{"TOKEN": "SYNTHETIC_AUTHORIZED_CACHE"})
			temporary.ExpiresAt = &expiry
			must(t, e.AcceptSnapshot(snapshot(1, temporary), testNow))
			must(t, e.Activate("temporary", 1, testNow))
			reconcile(t, e, p, testNow)
			if logout {
				must(t, e.Logout())
			} else {
				if e.Reconcile(context.Background(), unavailableProvider{}, expiry) == nil {
					t.Fatal("provider failure expected")
				}
			}
			persisted, _ := store.Load()
			if len(persisted.Managed) != 0 || len(persisted.Cloud.Environments) != 0 || len(persisted.Overrides) != 0 {
				t.Fatal("unauthorized cached plaintext retained")
			}
			if _, ok := persisted.Originals["TOKEN"]; !ok {
				t.Fatal("pending restoration lost")
			}
			reconcile(t, e, p, expiry)
			if p.values["TOKEN"] != "original" {
				t.Fatal("provider recovery did not restore original")
			}
		})
	}
}

func TestLocalSessionEpochRejectsInFlightSnapshotAndPersists(t *testing.T) {
	e, store, _ := newTest(t)
	epoch := e.State().SessionEpoch
	must(t, e.Logout())
	if !errors.Is(e.AcceptSnapshotAtEpoch(snapshot(1, env("one", map[string]string{"TOKEN": "old-response"})), testNow, epoch), ErrLocalSession) {
		t.Fatal("old session response accepted")
	}
	restarted, err := New(store)
	must(t, err)
	if restarted.State().SessionEpoch != epoch+1 || restarted.State().Cloud.AccountID != "" {
		t.Fatal("logout epoch was not persisted")
	}
	must(t, restarted.AcceptSnapshotAtEpoch(snapshot(1, env("one", map[string]string{"TOKEN": "new-response"})), testNow, restarted.State().SessionEpoch))
}
