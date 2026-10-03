package mobileworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

type dagNativeSlot struct {
	mu      sync.Mutex
	packet  []byte
	fail    bool
	entered chan struct{}
	resume  chan struct{}
}

func (s *dagNativeSlot) save(b []byte) error {
	s.mu.Lock()
	entered, resume := s.entered, s.resume
	s.entered, s.resume = nil, nil
	s.mu.Unlock()
	if entered != nil {
		close(entered)
		<-resume
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("synthetic atomic save failure")
	}
	s.packet = bytes.Clone(b)
	return nil
}
func (s *dagNativeSlot) check(expected string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if protectedStateHash(s.packet) != expected {
		return syncclient.ErrDAGJournalConflict
	}
	return nil
}
func (s *dagNativeSlot) cas(expected string, b []byte) error {
	s.mu.Lock()
	entered, resume := s.entered, s.resume
	s.entered, s.resume = nil, nil
	s.mu.Unlock()
	if entered != nil {
		close(entered)
		<-resume
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if protectedStateHash(s.packet) != expected {
		return syncclient.ErrDAGJournalConflict
	}
	if s.fail {
		return errors.New("synthetic atomic save failure")
	}
	s.packet = bytes.Clone(b)
	return nil
}
func (s *dagNativeSlot) read() []byte { s.mu.Lock(); defer s.mu.Unlock(); return bytes.Clone(s.packet) }
func dagMobileFixture(t *testing.T) (Config, *Workflow, *syncclient.CheckedDAGJournal, syncclient.ProtectedDAGOperation, *dagNativeSlot) {
	t.Helper()
	raw, err := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Pin   cryptox.PinnedIssuerRoot  `json:"rootPin"`
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("synthetic public DAG vector")
	}
	sub := f.Proof.Records[4].TransitionV2.Submission
	hash, err := cryptox.RecoveryTransitionHashV2(sub)
	if err != nil {
		t.Fatal(err)
	}
	gen, _ := strconv.ParseUint(f.Pin.AccountGeneration, 10, 64)
	slot := &dagNativeSlot{}
	config := testConfig(t)
	config.SaveProtectedState = slot.save
	config.SaveProtectedStateCAS = slot.cas
	config.CheckProtectedState = slot.check
	w, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	// Go component fixture only: this does not simulate Login or system authentication.
	w.state.AccountID, w.state.AccountGeneration = f.Pin.AccountID, f.Pin.AccountGeneration
	p := syncclient.ProtectedDAGOperation{Version: 1, Endpoint: w.state.Endpoint, AccountID: f.Pin.AccountID, AccountGeneration: gen, Pin: f.Pin, Kind: "transition-v2", OperationID: sub.Transition.OperationID, ContentHash: hash, Transition: &cryptox.RecoveryTransitionCommandV2{Submission: sub, DependencyBundle: cryptox.RecoveryDependencyBundle{Initialization: f.Proof.Initialization, Records: f.Proof.Records[:4]}}}
	j, err := w.newRecoveryDAGJournal()
	if err != nil {
		t.Fatal(err)
	}
	return config, w, j, p, slot
}
func TestMobileDAGJournalAtomicFailureReopenAndMetadataNeverTrusts(t *testing.T) {
	c, w, j, p, slot := dagMobileFixture(t)
	if err := j.Save(p); err != nil {
		t.Fatal(err)
	}
	before := slot.read()
	info, err := w.RecoveryDAGPendingInfo()
	if err != nil || info.TrustedDevice || info.Acceptance != "unknown" || info.OperationID != p.OperationID {
		t.Fatal("pending was trusted or guessed accepted", err)
	}
	p.Attempted = true
	slot.fail = true
	if err = j.Save(p); !errors.Is(err, ErrDAGPersistence) {
		t.Fatal("save failure hidden", err)
	}
	if !bytes.Equal(before, slot.read()) {
		t.Fatal("failed save changed durable state")
	}
	if w.state.RecoveryDAG == nil || bytes.Contains(w.state.RecoveryDAG.Journal, []byte(`"attempted":true`)) {
		t.Fatal("failed save advanced RAM")
	}
	if _, err = w.RecoveryDAGPendingInfo(); !errors.Is(err, ErrDAGPersistence) {
		t.Fatal("failed owner still usable", err)
	}
	if err = j.OwnerAlive(); !errors.Is(err, ErrDAGPersistence) {
		t.Fatal("old owner survived failed persistence", err)
	}
	if err = j.Save(p); !errors.Is(err, ErrDAGPersistence) {
		t.Fatal("old owner retried after failure", err)
	}
	w.Close()
	slot.fail = false
	c.ProtectedState = before
	reopened, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := reopened.newRecoveryDAGJournal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := next.Load()
	if err != nil || got.Attempted {
		t.Fatal("reopen applied failed state", err)
	}
	n, _ := strconv.ParseUint(p.Transition.Submission.Transition.ExpectedSequence, 10, 64)
	p.AcceptedSequence = n + 1
	p.Applied = true
	if err = next.Save(p); err != nil {
		t.Fatal(err)
	}
	info, err = reopened.RecoveryDAGPendingInfo()
	if err != nil || info.TrustedDevice || info.Acceptance != "accepted" || !info.OriginalApplied {
		t.Fatal("original acceptance became device trust", err)
	}
	if _, err = reopened.View(); !errors.Is(err, ErrRecoveryRestricted) {
		t.Fatal("accepted original enabled ordinary vault", err)
	}
	public, _ := json.Marshal(info)
	for _, secret := range [][]byte{[]byte("dependencyBundle"), []byte("transition" + `":{`), []byte("sessionHash"), []byte("nonce"), []byte("token")} {
		if bytes.Contains(public, secret) {
			t.Fatal("metadata exported original protocol packet")
		}
	}
}
func TestMobileDAGJournalLogoutWinsAfterInflightSaveAndOldOwnerCannotRecreate(t *testing.T) {
	c, w, j, p, slot := dagMobileFixture(t)
	if err := j.Save(p); err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	slot.entered, slot.resume = entered, resume
	p.Attempted = true
	saved := make(chan error, 1)
	go func() { saved <- j.Save(p) }()
	<-entered
	loggedOut := make(chan error, 1)
	go func() { loggedOut <- w.Logout() }()
	close(resume)
	if err := <-saved; err != nil {
		t.Fatal(err)
	}
	if err := <-loggedOut; err != nil {
		t.Fatal(err)
	}
	var closed protectedState
	if json.Unmarshal(slot.read(), &closed) != nil || !closed.Cloud.AccountClosed || closed.Cloud.SessionEpoch != 1 || closed.RecoveryDAG != nil {
		t.Fatal("logout tombstone did not replace original")
	}
	if err := j.Save(p); err == nil {
		t.Fatal("old owner recreated journal after logout")
	}
	c.ProtectedState = slot.read()
	reopened, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.newRecoveryDAGJournal(); !errors.Is(err, ErrDAGProtectedState) {
		t.Fatal("closed account minted another owner", err)
	}
}
func TestMobileDAGJournalRejectsEpochAndMutuallyExclusiveSchemasBeforeNetwork(t *testing.T) {
	c, w, j, p, slot := dagMobileFixture(t)
	if err := j.Save(p); err != nil {
		t.Fatal(err)
	}
	raw := slot.read()
	var original protectedState
	if json.Unmarshal(raw, &original) != nil {
		t.Fatal("decode")
	}
	changes := map[string]func(*protectedState){
		"profile":      func(s *protectedState) { s.RecoveryDAG.Profile = "issuer-recovery-v1" },
		"version":      func(s *protectedState) { s.RecoveryDAG.Version = 2 },
		"epoch":        func(s *protectedState) { s.Cloud.SessionEpoch++ },
		"closed":       func(s *protectedState) { s.Cloud.AccountClosed = true },
		"synthetic":    func(s *protectedState) { s.Cloud.Synthetic = true },
		"device":       func(s *protectedState) { s.RecoveryDAG.DeviceID = "other" },
		"key":          func(s *protectedState) { s.RecoveryDAG.SigningPublicKey = s.ReceivingPublicKey },
		"endpoint":     func(s *protectedState) { s.RecoveryDAG.Endpoint = "https://other.invalid" },
		"account":      func(s *protectedState) { s.RecoveryDAG.AccountID = "other" },
		"generation":   func(s *protectedState) { s.RecoveryDAG.AccountGeneration++ },
		"root":         func(s *protectedState) { s.Root = &cryptox.TrustRoot{} },
		"init":         func(s *protectedState) { s.Pending = &pendingInitialization{} },
		"oldRecovery":  func(s *protectedState) { s.Recovery = &recoveryRecord{} },
		"oldAuthority": func(s *protectedState) { s.RecoveryAuthority = &recoveryAuthorityRecord{} },
		"oldRecovered": func(s *protectedState) { s.RecoveredDevice = &recoveredDeviceRecord{} },
		"enrollment":   func(s *protectedState) { s.EnrollmentV3 = &mobileEnrollmentRecord{} },
		"approval":     func(s *protectedState) { s.PendingApproval = &approvalRecord{} },
		"approval3":    func(s *protectedState) { s.PendingApprovalV3 = &approvalRecordV3{} },
		"approval4":    func(s *protectedState) { s.PendingApprovalV4 = &approvalRecordV4{} },
		"management":   func(s *protectedState) { s.Management = &managementState{} },
		"selfRevoke":   func(s *protectedState) { s.SelfRevocation = []byte("synthetic") },
		"writes":       func(s *protectedState) { s.WriteJournal = []byte("synthetic") },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			candidate := clone(original)
			change(&candidate)
			c.ProtectedState, _ = json.Marshal(candidate)
			// Model an authenticated native snapshot containing this schema, so
			// rejection cannot be satisfied merely by a stale whole-state hash.
			if err := slot.save(c.ProtectedState); err != nil {
				t.Fatal(err)
			}
			expected := protectedStateHash(c.ProtectedState)
			if err := slot.check(expected); err != nil {
				t.Fatal("schema fixture did not match native CAS expectation", err)
			}
			engine, err := localstate.New(&memoryStore{state: candidate.Cloud})
			if err != nil {
				t.Fatal("schema fixture could not reach DAG validator", err)
			}
			checks := 0
			probe := &Workflow{state: candidate, engine: engine, saveNativeCAS: slot.cas, protectedSHA256: expected, checkNativeState: func(hash string) error {
				checks++
				return slot.check(hash)
			}}
			if err = probe.validateDAGStateLocked(); !errors.Is(err, ErrDAGProtectedState) || checks != 1 || probe.dagPersistenceFailed {
				t.Fatal("expected typed/schema rejection after matching native state", err, checks)
			}
			if other, err := New(c); err == nil {
				other.Close()
				t.Fatal("mixed or stale DAG state accepted")
			}
		})
	}
	var network atomic.Int32
	c.ProtectedState = raw
	if err := slot.save(raw); err != nil {
		t.Fatal(err)
	}
	c.HTTPClient = &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		network.Add(1)
		return nil, errors.New("synthetic network must stay unused")
	}}}
	reopened, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.Pull(context.Background()); !errors.Is(err, ErrRecoveryRestricted) {
		t.Fatal("ordinary pull reached DAG pending", err)
	}
	if err = reopened.Login(context.Background(), "synthetic@example.invalid", "not-a-real-password"); !errors.Is(err, ErrRecoveryRestricted) {
		t.Fatal("login replaced DAG pending", err)
	}
	if _, _, err = reopened.BeginRecoveryAuthoritySession(context.Background(), "not-a-real-code"); !errors.Is(err, ErrRecoveryRestricted) {
		t.Fatal("old recovery consumed DAG state", err)
	}
	if network.Load() != 0 {
		t.Fatal("invalid native state reached network")
	}
	w.mu.Lock()
	state := w.engine.State()
	state.SessionEpoch++
	w.store.state = state
	w.engine, _ = localstate.New(w.store)
	w.mu.Unlock()
	if err = j.OwnerAlive(); err == nil {
		t.Fatal("old epoch remained live")
	}
}

func TestMobileDAGIndependentWorkflowTombstoneRejectsOldWholeStateCAS(t *testing.T) {
	c, first, j, p, slot := dagMobileFixture(t)
	if err := j.Save(p); err != nil {
		t.Fatal(err)
	}
	c.ProtectedState = slot.read()
	second, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	observer, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	observerJournal, err := observer.newRecoveryDAGJournal()
	if err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resume) }) }
	defer release()
	slot.entered, slot.resume = entered, resume
	p.Attempted = true
	done := make(chan error, 1)
	go func() { done <- j.Save(p) }()
	<-entered // 第一对象已核本机 epoch/旧字节，尚未在 native CAS 锁内提交。
	if err = second.Logout(); err != nil {
		t.Fatal(err)
	}
	tombstone := slot.read()
	release()
	if err = <-done; !errors.Is(err, ErrDAGPersistence) {
		t.Fatal("stale Workflow overwrote another Workflow logout", err)
	}
	if !bytes.Equal(tombstone, slot.read()) {
		t.Fatal("whole-state tombstone changed")
	}
	if _, err = first.RecoveryDAGPendingInfo(); !errors.Is(err, ErrDAGPersistence) {
		t.Fatal("stale Workflow remained live", err)
	}
	if err = observerJournal.OwnerAlive(); !errors.Is(err, ErrDAGProtectedState) {
		t.Fatal("read-only old owner stayed live after independent logout", err)
	}
}
func TestMobileDAGRequiresAtomicNativeStoreAndCloseInvalidatesJournal(t *testing.T) {
	c, w, j, _, _ := dagMobileFixture(t)
	w.Close()
	if j.OwnerAlive() == nil {
		t.Fatal("closed authenticated Workflow retained journal")
	}
	c.SaveProtectedStateCAS = nil
	plain, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	plain.state.AccountID = "synthetic-account"
	plain.state.AccountGeneration = "1"
	if _, err = plain.newRecoveryDAGJournal(); !errors.Is(err, ErrDAGAtomicStoreRequired) {
		t.Fatal("Save-only provider enabled DAG", err)
	}
}
