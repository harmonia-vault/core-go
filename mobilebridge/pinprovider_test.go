package mobilebridge

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/harmonia-vault/core-go/appsecurity"
)

type pinNativeLife struct {
	retired atomic.Int32
	fail    atomic.Bool
}

func (l *pinNativeLife) RetireOwners() error {
	l.retired.Add(1)
	if l.fail.Load() {
		return errors.New("synthetic retirement failure")
	}
	return nil
}

type pinNativeStore struct {
	mu                       sync.Mutex
	locked                   atomic.Bool
	state                    appsecurity.AttemptState
	commits, releases, saves int
	failCommit, failRelease  int
	failSave                 bool
	packet                   []byte
	loadOverride             string
	beforeCommit             func(int)
}

func (s *pinNativeStore) Acquire() error {
	if !s.locked.CompareAndSwap(false, true) {
		return appsecurity.ErrBusy
	}
	return nil
}
func (s *pinNativeStore) Release() error {
	if !s.locked.CompareAndSwap(true, false) {
		return errors.New("synthetic lock not held")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releases++
	if s.releases == s.failRelease {
		return errors.New("synthetic release failure")
	}
	return nil
}
func (s *pinNativeStore) LoadAttempts() (string, error) {
	if !s.locked.Load() {
		return "", errors.New("synthetic load outside whole-attempt lock")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadOverride != "" {
		return s.loadOverride, nil
	}
	raw, e := json.Marshal(s.state)
	return string(raw), e
}
func (s *pinNativeStore) CommitAttempts(expected int64, next string) error {
	if !s.locked.Load() {
		return errors.New("synthetic commit outside whole-attempt lock")
	}
	s.mu.Lock()
	s.commits++
	n := s.commits
	hook := s.beforeCommit
	s.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n == s.failCommit {
		return errors.New("synthetic durable write failure")
	}
	if uint64(expected) != s.state.Revision {
		return errors.New("synthetic CAS rejected")
	}
	var a appsecurity.AttemptState
	if json.Unmarshal([]byte(next), &a) != nil {
		return errors.New("synthetic bad attempts")
	}
	s.state = a
	return nil
}
func (s *pinNativeStore) SaveWorkflowSealed(packet []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	if s.failSave {
		return errors.New("synthetic native workflow save failure")
	}
	s.packet = bytes.Clone(packet)
	return nil
}

type nativePINFixture struct {
	scope  string
	record []byte
	state  appsecurity.AttemptState
	life   *pinNativeLife
}

func newNativePINFixture(t *testing.T) nativePINFixture {
	t.Helper()
	life := &pinNativeLife{}
	setup, e := NewLocalPINSetup("org.harmonia.fixture.pin", "synthetic-pin/v1", "isolated-slot", "https://vault.example.invalid", life)
	if e != nil {
		t.Fatal(e)
	}
	defer setup.Close()
	scope, e := setup.ScopeJSON()
	if e != nil {
		t.Fatal(e)
	}
	pin, reentry := []byte("135790"), []byte("135790")
	provision, e := setup.Create(pin, reentry)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(pin, make([]byte, len(pin))) || !bytes.Equal(reentry, make([]byte, len(reentry))) || setup.setup != nil {
		t.Fatal("temporary setup material retained")
	}
	var result struct {
		Profile  string                   `json:"profile"`
		Record   string                   `json:"recordBase64"`
		Attempts appsecurity.AttemptState `json:"attempts"`
	}
	if json.Unmarshal(provision, &result) != nil || result.Profile != "harmonia/native-pin-provision/v1" {
		t.Fatal("invalid native provisioning packet")
	}
	record, e := base64.RawURLEncoding.DecodeString(result.Record)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(provision, []byte("HARMKEY1")) || bytes.Contains(provision, []byte("135790")) {
		t.Fatal("provision leaked synthetic PIN or clear material")
	}
	if _, e = setup.Create([]byte("135790"), []byte("135790")); !errors.Is(e, appsecurity.ErrClosed) {
		t.Fatal("setup could overwrite existing identity")
	}
	return nativePINFixture{scope, record, result.Attempts, life}
}
func (f nativePINFixture) open(t *testing.T) *LocalPINCore {
	t.Helper()
	p, e := OpenLocalPINCore("org.harmonia.fixture.pin", "synthetic-pin/v1", "isolated-slot", "https://vault.example.invalid", f.scope, f.life)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
func pinCommand(operation string) []byte {
	return []byte(`{"version":1,"endpoint":"https://vault.example.invalid","operation":"` + operation + `"}`)
}
func TestNativePINOneConsumeUsesMatureTrustGateAndClearsInputs(t *testing.T) {
	f := newNativePINFixture(t)
	p := f.open(t)
	s := &pinNativeStore{state: f.state}
	pin, input := []byte("135790"), pinCommand("view")
	out, e := p.Execute(pin, input, f.record, nil, nil, s)
	if e != nil {
		t.Fatal(e)
	}
	var result map[string]any
	if json.Unmarshal([]byte(out), &result) != nil || result["ok"] != false || result["code"] != "NOT_TRUSTED" || result["data"] != nil {
		t.Fatal("PIN was treated as cloud trust", out)
	}
	if !bytes.Equal(pin, make([]byte, len(pin))) || !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("native inputs retained")
	}
	if s.commits != 2 || s.state.Revision != 3 || s.state.Total != 1 || s.state.Failures != 0 || s.state.PendingAttempt != "" || s.locked.Load() || s.saves != 0 {
		t.Fatal("attempt did not settle/release before mature workflow")
	}
	if f.life.retired.Load() == 0 {
		t.Fatal("business rejection did not retire process owners")
	}
	if _, e = json.Marshal(p); !errors.Is(e, appsecurity.ErrNativeOnly) {
		t.Fatal("native core serialized")
	}
	if fmt.Sprintf("%#v", p) != "native local PIN core (opaque)" {
		t.Fatal("native core formatting exposed internals")
	}
}
func TestNativePINCorrectAndWrongPINUseDurableCountersAcrossNewInstance(t *testing.T) {
	f := newNativePINFixture(t)
	s := &pinNativeStore{state: f.state}
	p := f.open(t)
	if out, e := p.Execute([]byte("246802"), pinCommand("view"), f.record, nil, nil, s); out != "" || !errors.Is(e, appsecurity.ErrPIN) {
		t.Fatal("incorrect PIN accepted", e)
	}
	if s.state.Total != 1 || s.state.Failures != 1 || s.state.PendingAttempt == "" || s.commits != 1 {
		t.Fatal("failure was not charged before KDF")
	}
	_ = p.Close()
	reopened := f.open(t)
	if out, e := reopened.Execute([]byte("135790"), pinCommand("view"), f.record, nil, nil, s); e != nil || !strings.Contains(out, "NOT_TRUSTED") {
		t.Fatal("native reopen failed or bypassed trust", e)
	}
	if s.state.Total != 2 || s.state.Revision != 4 || s.state.Failures != 0 || s.commits != 3 {
		t.Fatal("restart reset counters")
	}
}
func TestNativePINPersistenceFailureNeverReachesBusiness(t *testing.T) {
	f := newNativePINFixture(t)
	for _, test := range []struct {
		name            string
		commit, release int
	}{{"precharge", 1, 0}, {"settle", 2, 0}, {"post-settle-release", 0, 2}} {
		t.Run(test.name, func(t *testing.T) {
			p := f.open(t)
			s := &pinNativeStore{state: f.state, failCommit: test.commit, failRelease: test.release}
			out, e := p.Execute([]byte("135790"), pinCommand("logout"), f.record, nil, nil, s)
			if out != "" || !errors.Is(e, appsecurity.ErrPersistence) || s.saves != 0 || f.life.retired.Load() == 0 {
				t.Fatal("uncertain native durability issued business lease", e)
			}
		})
	}
}
func TestNativePINStrictIntentRecordAndSignedNativeIntegersBeforeKDF(t *testing.T) {
	f := newNativePINFixture(t)
	for _, input := range [][]byte{pinCommand("beginRecoveryAuthority"), []byte(`{"version":1,"operation":"view","endpoint":"https://vault.example.invalid","operation":"logout"}`), []byte(`{"version":1,"operation":"view","endpoint":"https://other.example.invalid"}`), []byte(`{"version":1,"operation":"view","endpoint":"https://vault.example.invalid","authorization":true}`)} {
		p := f.open(t)
		s := &pinNativeStore{state: f.state}
		if out, e := p.Execute([]byte("135790"), input, f.record, nil, nil, s); out != "" || e == nil || s.commits != 0 {
			t.Fatal("unbound intent charged or executed")
		}
	}
	for _, raw := range []string{`{"revision":9223372036854775808}`, `{"revision":1,"revision":2}`, `{"revision":1,"state":"caller"}`, fmt.Sprintf(`{"revision":1,"recordHash":%q}`, f.state.RecordHash)} {
		p := f.open(t)
		s := &pinNativeStore{state: f.state, loadOverride: raw}
		if out, e := p.Execute([]byte("135790"), pinCommand("view"), f.record, nil, nil, s); out != "" || e == nil || s.commits != 0 {
			t.Fatal("native uint64/JSON truncation accepted")
		}
	}
	p := f.open(t)
	s := &pinNativeStore{state: f.state}
	bad := bytes.Replace(f.record, []byte(`"memoryKiB":65536`), []byte(`"memoryKiB":1`), 1)
	if out, e := p.Execute([]byte("135790"), pinCommand("view"), bad, nil, nil, s); out != "" || e == nil || s.commits != 0 {
		t.Fatal("untrusted KDF parameters charged/executed")
	}
	a := localPINAttempts{s}
	if a.Commit(math.MaxInt64+1, f.state) == nil || s.commits != 0 {
		t.Fatal("uint64 cast to native long")
	}
	if _, e := OpenLocalPINCore("org.harmonia.other", "synthetic-pin/v1", "isolated-slot", "https://vault.example.invalid", f.scope, f.life); e == nil {
		t.Fatal("cross-package record accepted")
	}
}
func TestNativePINCancelAndConcurrentBusyPreserveChargedAttempt(t *testing.T) {
	f := newNativePINFixture(t)
	p := f.open(t)
	entered, release := make(chan struct{}), make(chan struct{})
	s := &pinNativeStore{state: f.state, beforeCommit: func(n int) {
		if n == 1 {
			close(entered)
			<-release
		}
	}}
	done := make(chan error, 1)
	go func() { _, e := p.Execute([]byte("135790"), pinCommand("logout"), f.record, nil, nil, s); done <- e }()
	<-entered
	if out, e := p.Execute([]byte("135790"), pinCommand("view"), f.record, nil, nil, s); out != "" || !errors.Is(e, appsecurity.ErrBusy) {
		t.Fatal("concurrent operation bypassed busy")
	}
	close(release)
	if e := <-done; e == nil || s.commits != 1 || s.saves != 0 || s.state.Total != 1 || s.state.Failures != 1 || s.state.PendingAttempt == "" {
		t.Fatal("cancel lost durable charge or ran business", e)
	}
	if e := p.Cancel(); e != nil {
		t.Fatal(e)
	}
	if _, e := p.ScopeJSON(); !errors.Is(e, appsecurity.ErrClosed) {
		t.Fatal("canceled core revived")
	}
}
func TestNativePINWorkflowSaveAndRetirementFailuresStayHonest(t *testing.T) {
	f := newNativePINFixture(t)
	p := f.open(t)
	s := &pinNativeStore{state: f.state, failSave: true}
	out, e := p.Execute([]byte("135790"), pinCommand("logout"), f.record, nil, nil, s)
	if e != nil {
		t.Fatal(e)
	}
	var result map[string]any
	if json.Unmarshal([]byte(out), &result) != nil || result["ok"] != false || result["requiresDeviceDeletion"] != true || s.saves == 0 || len(s.packet) != 0 {
		t.Fatal("failed native save reported durable logout", out)
	}
	if _, e = p.ScopeJSON(); !errors.Is(e, appsecurity.ErrClosed) {
		t.Fatal("logout instance remained open")
	}
	p = f.open(t)
	s = &pinNativeStore{state: f.state}
	f.life.fail.Store(true)
	if out, e = p.Execute([]byte("246802"), pinCommand("view"), f.record, nil, nil, s); out != "" || !errors.Is(e, errPINLifecycle) {
		t.Fatal("failed retirement reported success", e)
	}
	if _, e = p.ScopeJSON(); !errors.Is(e, appsecurity.ErrClosed) {
		t.Fatal("failed owner retirement revived core")
	}
	f.life.fail.Store(false)
}
