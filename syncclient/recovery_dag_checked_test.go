package syncclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
)

func checkedOriginal(t *testing.T) ProtectedDAGOperation {
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
		t.Fatal("synthetic vector")
	}
	sub := f.Proof.Records[4].TransitionV2.Submission
	hash, err := cryptox.RecoveryTransitionHashV2(sub)
	if err != nil {
		t.Fatal(err)
	}
	gen, _ := strconv.ParseUint(f.Pin.AccountGeneration, 10, 64)
	return ProtectedDAGOperation{Version: 1, Endpoint: "https://synthetic.invalid", AccountID: f.Pin.AccountID, AccountGeneration: gen, Pin: f.Pin, Kind: "transition-v2", OperationID: sub.Transition.OperationID, ContentHash: hash, Transition: &cryptox.RecoveryTransitionCommandV2{Submission: sub, DependencyBundle: cryptox.RecoveryDependencyBundle{Initialization: f.Proof.Initialization, Records: f.Proof.Records[:4]}}}
}

type checkedCASStore struct {
	mu        sync.Mutex
	binding   DAGJournalBinding
	raw       []byte
	fail      bool
	beforeCAS func([]byte)
}

func (s *checkedCASStore) LoadDAGJournal(b DAGJournalBinding) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding != b {
		return nil, ErrDAGJournalConflict
	}
	if s.raw == nil {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(s.raw), nil
}
func (s *checkedCASStore) CompareAndSwapDAGJournal(b DAGJournalBinding, old, next []byte) error {
	if s.beforeCAS != nil {
		s.beforeCAS(next)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding != b || !EqualDAGJournalBytes(s.raw, old) {
		return ErrDAGJournalConflict
	}
	if s.fail {
		return errors.New("synthetic persistence failure")
	}
	s.raw = bytes.Clone(next)
	return nil
}
func TestCheckedDAGJournalSaveFailureReopenAndStrictMonotonicPacket(t *testing.T) {
	p := checkedOriginal(t)
	b := DAGJournalBinding{Endpoint: p.Endpoint, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, OwnerEpoch: 7}
	s := &checkedCASStore{binding: b}
	j, err := NewCheckedDAGJournal(s, b)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Save(p); err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(s.raw)
	p.Attempted = true
	s.fail = true
	if err = j.Save(p); err == nil || !bytes.Equal(original, s.raw) {
		t.Fatal("failure advanced storage")
	}
	s.fail = false
	reopened, err := NewCheckedDAGJournal(s, b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Load()
	if err != nil || got.Attempted {
		t.Fatal("failed save survived reopen", err)
	}
	if err = reopened.Save(p); err != nil {
		t.Fatal(err)
	}
	p.Attempted = false
	if reopened.Save(p) == nil {
		t.Fatal("attempted rollback")
	}
	p.Attempted = true
	n, _ := strconv.ParseUint(p.Transition.Submission.Transition.ExpectedSequence, 10, 64)
	p.AcceptedSequence = n + 1
	p.Applied = true
	if err = reopened.Save(p); err != nil {
		t.Fatal(err)
	}
	stable := bytes.Clone(s.raw)
	for name, edit := range map[string]func(*ProtectedDAGOperation){
		"applied":    func(x *ProtectedDAGOperation) { x.Applied = false },
		"accepted":   func(x *ProtectedDAGOperation) { x.AcceptedSequence = 0 },
		"content":    func(x *ProtectedDAGOperation) { x.ContentHash = "" },
		"id":         func(x *ProtectedDAGOperation) { x.OperationID = "other-id" },
		"kind":       func(x *ProtectedDAGOperation) { x.Kind = "recovered-v2" },
		"endpoint":   func(x *ProtectedDAGOperation) { x.Endpoint = "https://another.invalid" },
		"account":    func(x *ProtectedDAGOperation) { x.AccountID = "other" },
		"generation": func(x *ProtectedDAGOperation) { x.AccountGeneration++ },
		"pin":        func(x *ProtectedDAGOperation) { x.Pin.DeviceID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			x := cloneDAGOperation(p)
			edit(&x)
			if reopened.Save(x) == nil || !bytes.Equal(s.raw, stable) {
				t.Fatal("mutation changed original")
			}
		})
	}
	for _, raw := range [][]byte{append([]byte(`{"ownerEpoch":7,`), stable[1:]...), append(bytes.Clone(stable), []byte(" {}")...), bytes.Repeat([]byte{' '}, cryptox.MaxRecoveryAuthorityBytes+4097)} {
		if _, err = DecodeDAGJournal(b, raw); err == nil {
			t.Fatal("ambiguous/oversize record")
		}
	}
	b.OwnerEpoch++
	if _, err = DecodeDAGJournal(b, stable); err == nil {
		t.Fatal("other epoch decoded original")
	}
}
func TestCheckedDAGJournalConcurrentOwnersCannotOverwriteAcceptedRecord(t *testing.T) {
	p := checkedOriginal(t)
	b := DAGJournalBinding{Endpoint: p.Endpoint, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration}
	s := &checkedCASStore{binding: b}
	first, err := NewCheckedDAGJournal(s, b)
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Save(p); err != nil {
		t.Fatal(err)
	}
	second, err := NewCheckedDAGJournal(s, b)
	if err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	s.beforeCAS = func(next []byte) {
		if bytes.Contains(next, []byte(`"attempted":true`)) {
			close(entered)
			<-resume
		}
	}
	pending := cloneDAGOperation(p)
	pending.Attempted = true
	done := make(chan error, 1)
	go func() { done <- first.Save(pending) }()
	<-entered
	accepted := cloneDAGOperation(p)
	n, _ := strconv.ParseUint(p.Transition.Submission.Transition.ExpectedSequence, 10, 64)
	accepted.AcceptedSequence = n + 1
	accepted.Applied = true
	if err = second.Save(accepted); err != nil {
		t.Fatal(err)
	}
	close(resume)
	if err = <-done; !errors.Is(err, ErrDAGJournalConflict) {
		t.Fatal("stale writer overwrote accepted original", err)
	}
	got, err := second.Load()
	if err != nil || !got.Applied || got.AcceptedSequence != accepted.AcceptedSequence {
		t.Fatal("accepted record lost", err)
	}
}
