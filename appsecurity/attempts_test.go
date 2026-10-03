package appsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This adapter tests real temporary-file persistence and whole-attempt mutex.
// Android MAC/OS-file-lock/Keystore are separate future native acceptance.
type diskStore struct {
	mu           sync.Mutex
	path         string
	failCommit   uint64
	failRelease  bool
	commits      uint64
	beforeCommit func(AttemptState)
	afterCommit  func(AttemptState)
}

func newDiskStore(t *testing.T, s AttemptState) *diskStore {
	t.Helper()
	d := &diskStore{path: filepath.Join(t.TempDir(), "synthetic-attempts.json")}
	if e := d.write(s); e != nil {
		t.Fatal(e)
	}
	return d
}
func (d *diskStore) Acquire() error {
	if !d.mu.TryLock() {
		return ErrBusy
	}
	return nil
}
func (d *diskStore) Release() error {
	d.mu.Unlock()
	if d.failRelease {
		return errors.New("synthetic release failure")
	}
	return nil
}
func (d *diskStore) Load() (AttemptState, error) {
	var s AttemptState
	b, e := os.ReadFile(d.path)
	if e == nil {
		e = json.Unmarshal(b, &s)
	}
	return s, e
}
func (d *diskStore) write(s AttemptState) error {
	data, e := json.Marshal(s)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(d.path+".new", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(d.path+".new", d.path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(d.path))
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = dir.Sync(); e != nil {
		return e
	}
	got, e := os.ReadFile(d.path)
	if e != nil || string(got) != string(data) {
		return ErrPersistence
	}
	return nil
}
func (d *diskStore) Commit(revision uint64, next AttemptState) error {
	current, e := d.Load()
	if e != nil || current.Revision != revision {
		return ErrState
	}
	d.commits++
	if d.beforeCommit != nil {
		d.beforeCommit(next)
	}
	if d.commits == d.failCommit {
		return errors.New("synthetic commit failure")
	}
	if e := d.write(next); e != nil {
		return e
	}
	if d.afterCommit != nil {
		d.afterCommit(next)
	}
	return nil
}
func TestPINPrechargeAndSettleFailuresNeverIssueLease(t *testing.T) {
	for _, phase := range []uint64{1, 2} {
		t.Run(map[uint64]string{1: "precharge", 2: "settle"}[phase], func(t *testing.T) {
			r, s, b, _ := fixture(t)
			store := newDiskStore(t, s)
			retired := false
			p, e := NewProvider(r, b, store, func() { retired = true })
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			store.failCommit = phase
			lease, e := p.Unlock(context.Background(), []byte("12345678"), strings.Repeat("a", 64))
			if !errors.Is(e, ErrPersistence) || lease != nil || !retired {
				t.Fatal("save failure issued lease or did not synchronously retire", e)
			}
			state, e := store.Load()
			if e != nil {
				t.Fatal(e)
			}
			if phase == 1 && state.Total != 0 || phase == 2 && (state.Total != 1 || state.Failures != 1 || state.PendingAttempt == "") {
				t.Fatal("uncertain save silently reset charge")
			}
			if _, e = p.Unlock(context.Background(), []byte("12345678"), strings.Repeat("a", 64)); !errors.Is(e, ErrClosed) {
				t.Fatal("failed provider reused material", e)
			}
		})
	}
}
func TestPINInterruptedChargeAndRecreatedProviderKeepAttemptBudget(t *testing.T) {
	for i, a := range os.Args {
		if a == "appsecurity-charge-child" && len(os.Args) == i+4 {
			data, e := os.ReadFile(os.Args[i+1])
			if e != nil {
				t.Fatal(e)
			}
			var r Record
			if e = json.Unmarshal(data, &r); e != nil {
				t.Fatal(e)
			}
			store := &diskStore{path: os.Args[i+2]}
			store.afterCommit = func(s AttemptState) {
				if s.PendingAttempt != "" {
					if e := os.WriteFile(os.Args[i+3], []byte("charged"), 0600); e != nil {
						t.Fatal(e)
					}
					<-time.After(time.Hour)
				}
			}
			p, e := NewProvider(r, r.Binding, store, func() {})
			if e != nil {
				t.Fatal(e)
			}
			_, _ = p.Unlock(context.Background(), []byte("12345678"), strings.Repeat("b", 64))
			t.Fatal("child unexpectedly escaped durable charge pause")
		}
	}
	r, s, b, _ := fixture(t)
	store := newDiskStore(t, s)
	data, _ := r.Encode()
	recordPath := filepath.Join(filepath.Dir(store.path), "synthetic-sealed-record.json")
	ready := filepath.Join(filepath.Dir(store.path), "charged.marker")
	if e := os.WriteFile(recordPath, data, 0600); e != nil {
		t.Fatal(e)
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	child := exec.Command(binary, "-test.run=^TestPINInterruptedChargeAndRecreatedProviderKeepAttemptBudget$", "--", "appsecurity-charge-child", recordPath, store.path, ready)
	// Do not copy the user's environment. No PIN/material is supplied as an arg.
	child.Env = []string{"PATH=/usr/bin:/bin", "TZ=UTC"}
	var output bytes.Buffer
	child.Stdout = &output
	child.Stderr = &output
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, e = os.Stat(ready); e == nil {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("synthetic child did not persist charge")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e = child.Wait(); e == nil {
		t.Fatal("charge child was not interrupted")
	}
	persisted, e := store.Load()
	if e != nil || persisted.Total != 1 || persisted.Failures != 1 || persisted.PendingAttempt == "" {
		t.Fatal("real killed child lost durable charge", e)
	}
	var retired atomic.Int32
	reopened, e := NewProvider(r, b, store, func() { retired.Add(1) })
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if _, e = reopened.Unlock(context.Background(), []byte("12345679"), strings.Repeat("b", 64)); !errors.Is(e, ErrPIN) {
		t.Fatal("wrong PIN accepted after child interruption", e)
	}
	state, e := store.Load()
	if e != nil || state.Total != 2 || state.Failures != 2 || state.PendingAttempt == "" || retired.Load() == 0 {
		t.Fatal("recreated provider reset durable charge", e)
	}
	if e = os.Remove(store.path); e != nil {
		t.Fatal(e)
	}
	if _, e = NewProvider(r, b, store, func() { retired.Add(1) }); !errors.Is(e, ErrPersistence) {
		t.Fatal("deleted limiter silently became zero", e)
	}
}

func TestPINWholeAttemptLockPreventsConcurrentKDFAndCharge(t *testing.T) {
	r, s, b, _ := fixture(t)
	store := newDiskStore(t, s)
	first, e := NewProvider(r, b, store, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	second, e := NewProvider(r, b, store, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	charged := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	store.beforeCommit = func(next AttemptState) {
		if next.PendingAttempt != "" {
			once.Do(func() { close(charged); <-release })
		}
	}
	result := make(chan *Lease, 1)
	fail := make(chan error, 1)
	go func() {
		l, e := first.Unlock(context.Background(), []byte("12345678"), strings.Repeat("c", 64))
		result <- l
		fail <- e
	}()
	<-charged
	if l, e := second.Unlock(context.Background(), []byte("12345678"), strings.Repeat("d", 64)); !errors.Is(e, ErrBusy) || l != nil {
		t.Fatal("second instance guessed while slot held", e)
	}
	close(release)
	l := <-result
	if e := <-fail; e != nil || l == nil {
		t.Fatal("first attempt failed", e)
	}
	l.Close()
	state, e := store.Load()
	if e != nil || state.Total != 1 || state.Failures != 0 || store.commits != 2 {
		t.Fatal("BUSY charged or ran second KDF", e)
	}
}
func TestPINRestartDelayDoesNotTrustWallClockAndRejectsCounterRollback(t *testing.T) {
	r, s, b, _ := fixture(t)
	s.Total = 5
	s.Failures = 5
	s.PendingAttempt = strings.Repeat("e", 64)
	s.DelaySeconds = 30
	s.Revision = 6
	store := newDiskStore(t, s)
	p, e := NewProvider(r, b, store, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if p.blockedUntil.Before(time.Now().Add(29 * time.Second)) {
		t.Fatal("restart did not impose full durable delay")
	}
	if _, e = p.Unlock(context.Background(), []byte("12345678"), strings.Repeat("f", 64)); !errors.Is(e, ErrLocked) || store.commits != 0 {
		t.Fatal("fresh restart escaped delay", e)
	}
	// A wall-clock value is intentionally absent from persisted state. Even a
	// same-revision counter rewrite or old revision is rejected in this process.
	changed := s
	changed.Failures = 0
	changed.DelaySeconds = 0
	changed.PendingAttempt = ""
	if e = store.write(changed); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Unlock(context.Background(), []byte("12345678"), strings.Repeat("f", 64)); !errors.Is(e, ErrState) {
		t.Fatal("same-revision counter rollback accepted", e)
	}
}
