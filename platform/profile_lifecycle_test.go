package platform

import (
	"errors"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

const profileTestSID = "S-1-5-21-111111111-222222222-333333333-1001"

var errProfileSynthetic = errors.New("synthetic profile failure")

type fakeProfileBackend struct {
	mu             sync.Mutex
	history        []string
	references     int
	loadErr        error
	partialLoad    bool
	openFailures   int
	unloadFailures int
	tokenFailures  int
	keyFailures    int
	key            *fakeProfileKey
	readEntered    chan struct{}
	finishRead     chan struct{}
}
type fakeProfileKey struct {
	backend *fakeProfileBackend
	sid     string
}

func newFakeProfile() *fakeProfileBackend {
	b := &fakeProfileBackend{references: 1} // 另一个模拟交互会话已有 profile 引用。
	b.key = &fakeProfileKey{backend: b, sid: profileTestSID}
	return b
}
func (b *fakeProfileBackend) record(action string) { b.history = append(b.history, action) }
func (b *fakeProfileBackend) calls() ([]string, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.history...), b.references
}
func (b *fakeProfileBackend) Load() (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("load")
	if b.loadErr != nil {
		if b.partialLoad {
			b.references++
		}
		return b.partialLoad, b.loadErr
	}
	b.references++
	return true, nil
}
func (b *fakeProfileBackend) OpenEnvironment() (closeableUserEnvironment, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("open-environment")
	if b.openFailures > 0 {
		b.openFailures--
		return nil, errProfileSynthetic
	}
	return b.key, nil
}
func (b *fakeProfileBackend) Unload() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("unload-owned-reference")
	if b.unloadFailures > 0 {
		b.unloadFailures--
		return errProfileSynthetic
	}
	b.references--
	return nil
}
func (b *fakeProfileBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("close-token")
	if b.tokenFailures > 0 {
		b.tokenFailures--
		return errProfileSynthetic
	}
	return nil
}
func (k *fakeProfileKey) UserSID() string { return k.sid }
func (k *fakeProfileKey) Read(name string) (RegistryValue, bool, error) {
	b := k.backend
	b.mu.Lock()
	b.record("read")
	entered, finish := b.readEntered, b.finishRead
	b.mu.Unlock()
	if entered != nil {
		close(entered)
		<-finish
	}
	return RegistryValue{Value: "synthetic-original", Expand: true}, true, nil
}
func (k *fakeProfileKey) Set(name string, value RegistryValue) error {
	k.backend.mu.Lock()
	defer k.backend.mu.Unlock()
	k.backend.record("set")
	return nil
}
func (k *fakeProfileKey) Delete(name string) error {
	k.backend.mu.Lock()
	defer k.backend.mu.Unlock()
	k.backend.record("delete")
	return nil
}
func (k *fakeProfileKey) Notify() error {
	k.backend.mu.Lock()
	defer k.backend.mu.Unlock()
	k.backend.record("notify")
	return nil
}
func (k *fakeProfileKey) Close() error {
	b := k.backend
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("close-key")
	if b.keyFailures > 0 {
		b.keyFailures--
		return errProfileSynthetic
	}
	return nil
}
func profileStore(t *testing.T, b *fakeProfileBackend) *ProfileEnvironmentStore {
	t.Helper()
	store, err := newProfileEnvironmentStore(profileTestSID, b)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestProfileStopWaitsForReadAndRejectsQueuedWrite(t *testing.T) {
	b := newFakeProfile()
	b.readEntered = make(chan struct{})
	b.finishRead = make(chan struct{})
	s := profileStore(t, b)
	readDone := make(chan error, 1)
	go func() { _, _, err := s.Read("TOKEN"); readDone <- err }()
	select {
	case <-b.readEntered:
	case <-time.After(time.Second):
		t.Fatal("read did not start")
	}
	stopDone := make(chan error, 1)
	go func() { stopDone <- s.Close() }()
	deadline := time.Now().Add(time.Second)
	for !s.stopping.Load() {
		if time.Now().After(deadline) {
			t.Fatal("stop was not announced")
		}
		runtime.Gosched()
	}
	writeDone := make(chan error, 1)
	go func() { writeDone <- s.Set("TOKEN", RegistryValue{Value: "synthetic-next"}) }()
	calls, refs := b.calls()
	if !reflect.DeepEqual(calls, []string{"load", "open-environment", "read"}) || refs != 2 {
		t.Fatalf("closed an in-flight or foreign reference: %v, %d", calls, refs)
	}
	close(b.finishRead)
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; !errors.Is(err, ErrProfileClosed) {
		t.Fatalf("queued write accepted after stop: %v", err)
	}
	calls, refs = b.calls()
	if refs != 1 || !reflect.DeepEqual(calls, []string{"load", "open-environment", "read", "close-key", "unload-owned-reference", "close-token"}) {
		t.Fatalf("bad lifecycle %v, %d", calls, refs)
	}
	if _, _, err := s.Read("TOKEN"); !errors.Is(err, ErrProfileClosed) {
		t.Fatalf("stopped store revived: %v", err)
	}
}
func TestProfileFailureCleanupNeverRevivesOrUnloadsForeignSession(t *testing.T) {
	b := newFakeProfile()
	b.keyFailures = 1
	b.unloadFailures = 1
	b.tokenFailures = 1
	s := profileStore(t, b)
	if _, _, err := s.Read("TOKEN"); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := s.Close(); !errors.Is(err, errProfileSynthetic) {
			t.Fatalf("cleanup attempt %d: %v", attempt, err)
		}
		if err := s.Delete("TOKEN"); !errors.Is(err, ErrProfileClosed) {
			t.Fatalf("revived after failed cleanup: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	calls, refs := b.calls()
	expected := []string{"load", "open-environment", "read", "close-key", "close-key", "unload-owned-reference", "unload-owned-reference", "close-token", "close-token"}
	if refs != 1 || !reflect.DeepEqual(calls, expected) {
		t.Fatalf("lost cleanup ownership: %v, %d", calls, refs)
	}
}
func TestProfileLoadFailureDoesNotReleaseUnownedProfile(t *testing.T) {
	b := newFakeProfile()
	b.loadErr = errProfileSynthetic
	s := profileStore(t, b)
	if _, _, err := s.Read("TOKEN"); !errors.Is(err, errProfileSynthetic) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	calls, refs := b.calls()
	if refs != 1 || !reflect.DeepEqual(calls, []string{"load", "close-token"}) {
		t.Fatalf("unloaded unowned profile %v, %d", calls, refs)
	}
}
func TestProfileOpenFailureRetainsSingleOwnedLease(t *testing.T) {
	b := newFakeProfile()
	b.openFailures = 1
	s := profileStore(t, b)
	if _, _, err := s.Read("TOKEN"); !errors.Is(err, errProfileSynthetic) {
		t.Fatal(err)
	}
	if _, _, err := s.Read("TOKEN"); err != nil {
		t.Fatal(err)
	}
	if err := s.Notify(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	calls, refs := b.calls()
	if refs != 1 || !reflect.DeepEqual(calls, []string{"load", "open-environment", "open-environment", "read", "notify", "close-key", "unload-owned-reference", "close-token"}) {
		t.Fatalf("lost lease on child open failure %v, %d", calls, refs)
	}
}
func TestProfileIdentityMismatchStopsBeforeReadingOrWriting(t *testing.T) {
	b := newFakeProfile()
	b.key.sid = "S-1-5-21-111111111-222222222-333333333-1002"
	s := profileStore(t, b)
	if _, _, err := s.Read("TOKEN"); !errors.Is(err, ErrProfileIdentity) {
		t.Fatal(err)
	}
	if err := s.Set("TOKEN", RegistryValue{Value: "synthetic"}); !errors.Is(err, ErrProfileClosed) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	calls, refs := b.calls()
	if refs != 1 || !reflect.DeepEqual(calls, []string{"load", "open-environment", "close-key", "unload-owned-reference", "close-token"}) {
		t.Fatalf("crossed SID boundary %v, %d", calls, refs)
	}
}
func TestProfileConcurrentStopReleasesOwnedReferenceOnce(t *testing.T) {
	b := newFakeProfile()
	s := profileStore(t, b)
	if err := s.Set("TOKEN", RegistryValue{Value: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.Close() }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	calls, refs := b.calls()
	if refs != 1 || !reflect.DeepEqual(calls, []string{"load", "open-environment", "set", "close-key", "unload-owned-reference", "close-token"}) {
		t.Fatalf("duplicated stop %v, %d", calls, refs)
	}
}
func TestProfileInvalidInputsNeverLoad(t *testing.T) {
	b := newFakeProfile()
	s := profileStore(t, b)
	for _, name := range []string{"", `Other\TOKEN`, "__harmonia_internal", "TOKEN\x00"} {
		if _, _, err := s.Read(name); err == nil {
			t.Fatalf("read accepted %q", name)
		}
		if err := s.Delete(name); err == nil {
			t.Fatalf("delete accepted %q", name)
		}
	}
	if err := s.Set("TOKEN", RegistryValue{Value: "synthetic\x00value"}); err == nil {
		t.Fatal("accepted NUL")
	}
	calls, _ := b.calls()
	if len(calls) != 0 {
		t.Fatalf("loaded profile before input validation: %v", calls)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestProfileLocalPathRejectsNamespaceAndAmbiguity(t *testing.T) {
	for _, value := range []string{`C:\Profiles\HarmoniaTest`, `D:\Profiles\合成 测试`} {
		if !profileLocalPath(value) {
			t.Errorf("rejected ordinary local path %q", value)
		}
	}
	for _, value := range []string{`C:\`, `C:\Profiles\..\Other`, `C:\Profiles\Test.`, `C:\Profiles\Test `, `\\server\Profiles\Test`, `\\?\C:\Profiles\Test`, `C:\Profiles\Test:stream`, `C:\Profiles\%USERNAME%`, `C:\Profiles\\Test`, `C:/Profiles/Test`, `C:\Profiles\NUL.dat`, `C:\Profiles\COM1`} {
		if profileLocalPath(value) {
			t.Errorf("accepted ambiguous path %q", value)
		}
	}
}

func TestProfilePartialLoadFailureRetainsCleanupOwnership(t *testing.T) {
	b := newFakeProfile()
	b.loadErr = errProfileSynthetic
	b.partialLoad = true
	s := profileStore(t, b)
	if _, _, err := s.Read("TOKEN"); !errors.Is(err, errProfileSynthetic) {
		t.Fatal(err)
	}
	if err := s.Set("TOKEN", RegistryValue{Value: "synthetic"}); !errors.Is(err, ErrProfileClosed) {
		t.Fatalf("partial failure reopened store: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	calls, refs := b.calls()
	if refs != 1 || !reflect.DeepEqual(calls, []string{"load", "unload-owned-reference", "close-token"}) {
		t.Fatalf("lost acquired reference after failed validation: %v, %d", calls, refs)
	}
}
