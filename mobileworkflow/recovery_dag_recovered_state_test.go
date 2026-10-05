package mobileworkflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
	"os"
	"sync/atomic"
	"testing"
)

func TestMobileDAGRecoveredAtomicPromotionColdState(t *testing.T) {
	c, w, j, p, next, slot := b3MobileFixture(t)
	s, e := w.newDAGPreparationStore()
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []syncclient.DAGRecoveredPreparation{b3Intent(p), p} {
		if e = s.SaveRecoveredPreparation(v); e != nil {
			t.Fatal(e)
		}
		c.ProtectedState = slot.read()
		cold, e := New(c)
		if e != nil {
			t.Fatal(e)
		}
		info, e := cold.DAGRecoveredDeviceInfo()
		if e != nil || info.Phase != v.Phase || info.OperationID != p.OperationID || info.TrustedDevice || !info.NeedsOriginalOwner || info.State != "interrupted-original" {
			t.Fatal("cold metadata", e)
		}
		if _, e = cold.RecoveryDAGPendingInfo(); !errors.Is(e, ErrDAGPreparationInterrupted) {
			t.Fatal("prep not sealed", e)
		}
		if _, e = cold.View(); !errors.Is(e, ErrRecoveryRestricted) {
			t.Fatal("prep exposed view", e)
		}
		cold.Close()
	}
	if e = j.Save(next); e != nil {
		t.Fatal("whole-state promotion", e)
	}
	if _, e = s.LoadRecoveredPreparation(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("prep residue", e)
	}
	c.ProtectedState = slot.read()
	cold, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer cold.Close()
	info, e := cold.DAGRecoveredDeviceInfo()
	if e != nil || info.OperationID != next.OperationID || info.State != "pending-original" || info.TrustedDevice || info.OriginalConfirmed {
		t.Fatal("cold packet", e)
	}
}
func TestMobileDAGRecoveredCASFailureRetiresAndPreserves(t *testing.T) {
	for _, phase := range []string{"intent", "challenged", "sealed"} {
		t.Run(phase, func(t *testing.T) {
			c, w, j, p, next, slot := b3MobileFixture(t)
			s, _ := w.newDAGPreparationStore()
			if phase != "intent" {
				if e := s.SaveRecoveredPreparation(b3Intent(p)); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "sealed" {
				if e := s.SaveRecoveredPreparation(p); e != nil {
					t.Fatal(e)
				}
			}
			before := slot.read()
			ram := clone(w.state)
			var canceled atomic.Int32
			w.dagOwnerCancel = func() { canceled.Add(1) }
			slot.fail = true
			var e error
			switch phase {
			case "intent":
				e = s.SaveRecoveredPreparation(b3Intent(p))
			case "challenged":
				e = s.SaveRecoveredPreparation(p)
			case "sealed":
				e = j.Save(next)
			}
			if !errors.Is(e, ErrDAGPersistence) || canceled.Load() != 1 || !bytes.Equal(before, slot.read()) || !sameJSONValue(ram, w.state) {
				t.Fatal("failed CAS advanced/kept owner", e)
			}
			if _, e = s.LoadRecoveredPreparation(); !errors.Is(e, ErrDAGPersistence) {
				t.Fatal("failed owner revived", e)
			}
			slot.fail = false
			w.Close()
			c.ProtectedState = before
			cold, e := New(c)
			if e != nil {
				t.Fatal(e)
			}
			defer cold.Close()
			info, e := cold.DAGRecoveredDeviceInfo()
			if e != nil || info.TrustedDevice || info.Phase != map[string]string{"intent": "", "challenged": "intent", "sealed": "challenged"}[phase] {
				t.Fatal("reopen advanced", e)
			}
		})
	}
}
func TestMobileDAGRecoveredImmutableAndJointSchema(t *testing.T) {
	c, w, _, p, _, slot := b3MobileFixture(t)
	s, _ := w.newDAGPreparationStore()
	if e := s.SaveRecoveredPreparation(b3Intent(p)); e != nil {
		t.Fatal(e)
	}
	stable := slot.read()
	for _, edit := range []func(*syncclient.DAGRecoveredPreparation){func(p *syncclient.DAGRecoveredPreparation) { p.OperationID = "different-id" }, func(p *syncclient.DAGRecoveredPreparation) { p.ExpectedSequence++ }, func(p *syncclient.DAGRecoveredPreparation) {
		p.SelectedRights = p.SelectedRights[1:]
		p.SelectedRightsHash, _ = cryptox.RecoveredDeviceRightsHash(p.SelectedRights)
	}} {
		v := clone(b3Intent(p))
		edit(&v)
		if e := syncclient.ValidateDAGRecoveredPreparation(v); e != nil {
			t.Fatal("valid alternative prerequisite", e)
		}
		if e := s.SaveRecoveredPreparation(v); !errors.Is(e, syncclient.ErrDAGPreparationConflict) || !bytes.Equal(stable, slot.read()) {
			t.Fatal("replaced original intent", e)
		}
	}
	original := clone(w.state)
	for name, edit := range map[string]func(*protectedState){
		"epoch":                 func(s *protectedState) { s.RecoveryDAGRecoveredPreparation.OwnerEpoch++ },
		"scope":                 func(s *protectedState) { s.RecoveryDAGRecoveredPreparation.AccountID = "other-account" },
		"device":                func(s *protectedState) { s.RecoveryDAGRecoveredPreparation.DeviceID = "other-device" },
		"key":                   func(s *protectedState) { s.RecoveryDAGRecoveredPreparation.SigningPublicKey = s.ReceivingPublicKey },
		"closed":                func(s *protectedState) { s.Cloud.AccountClosed = true },
		"no-prior":              func(s *protectedState) { s.RecoveryDAG = nil },
		"transition-prep-mixed": func(s *protectedState) { s.RecoveryDAGPreparation = clone(s.RecoveryDAGRecoveredPreparation) },
		"root":                  func(s *protectedState) { s.Root = &cryptox.TrustRoot{} },
		"init":                  func(s *protectedState) { s.Pending = &pendingInitialization{} },
		"enrollment":            func(s *protectedState) { s.EnrollmentV5 = &mobileEnrollmentRecord{} },
		"approval4":             func(s *protectedState) { s.PendingApprovalV5 = &approvalRecordV5{} },
		"management":            func(s *protectedState) { s.Management = &managementState{} },
		"self-revoke":           func(s *protectedState) { s.SelfRevocation = []byte("synthetic") },
		"writes":                func(s *protectedState) { s.WriteJournal = []byte("synthetic") },
		"synthetic":             func(s *protectedState) { s.Cloud.Synthetic = true },
		"prior-not-applied": func(s *protectedState) {
			var m map[string]any
			_ = json.Unmarshal(s.RecoveryDAG.Journal, &m)
			record := m["operation"].(map[string]any)
			record["applied"] = false
			s.RecoveryDAG.Journal, _ = json.Marshal(m)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clone(original)
			edit(&candidate)
			raw, _ := json.Marshal(candidate)
			if e := slot.save(raw); e != nil {
				t.Fatal(e)
			}
			if e := slot.check(protectedStateHash(raw)); e != nil {
				t.Fatal("matched snapshot prerequisite", e)
			}
			engine, e := localstate.New(&memoryStore{state: candidate.Cloud})
			if e != nil {
				t.Fatal("validator prerequisite", e)
			}
			checks := 0
			probe := &Workflow{state: candidate, engine: engine, saveNativeCAS: slot.cas, protectedSHA256: protectedStateHash(raw), checkNativeState: func(hash string) error { checks++; return slot.check(hash) }}
			if e = probe.validateDAGStateLocked(); !errors.Is(e, ErrDAGProtectedState) || checks != 1 || probe.dagPersistenceFailed {
				t.Fatal("must reach typed validator after matching snapshot", e, checks)
			}
			if name == "prior-not-applied" {
				binding := syncclient.DAGJournalBinding{Endpoint: p.Endpoint, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, OwnerEpoch: candidate.Cloud.SessionEpoch}
				if _, e = syncclient.DecodeDAGJournal(binding, candidate.RecoveryDAG.Journal); e != nil {
					t.Fatal("prior itself must remain valid before joint Applied check", e)
				}
			}
			c.ProtectedState = raw
			bad, e := New(c)
			if e == nil {
				bad.Close()
				t.Fatal("joint schema accepted")
			}
		})
	}
}
func TestMobileDAGRecoveredConcurrentOwnersAndLogout(t *testing.T) {
	c, w, _, p, _, slot := b3MobileFixture(t)
	s, _ := w.newDAGPreparationStore()
	if e := s.SaveRecoveredPreparation(b3Intent(p)); e != nil {
		t.Fatal(e)
	}
	c.ProtectedState = slot.read()
	other, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	second, _ := other.newDAGPreparationStore()
	entered, resume := make(chan struct{}), make(chan struct{})
	slot.entered, slot.resume = entered, resume
	done := make(chan error, 1)
	go func() { done <- s.SaveRecoveredPreparation(p) }()
	<-entered
	winner := clone(p)
	winner.Challenge.ChallengeID = "winner-original-challenge"
	if e = second.SaveRecoveredPreparation(winner); e != nil {
		t.Fatal(e)
	}
	stable := slot.read()
	close(resume)
	if e = <-done; !errors.Is(e, syncclient.ErrDAGJournalConflict) || !bytes.Equal(stable, slot.read()) {
		t.Fatal("stale writer overwrote winner", e)
	}
	if e = other.Logout(); e != nil {
		t.Fatal(e)
	}
	stable = slot.read()
	if other.state.RecoveryDAGRecoveredPreparation != nil || other.state.RecoveryDAG != nil || !other.engine.State().AccountClosed {
		t.Fatal("logout retained original")
	}
	if e = second.SaveRecoveredPreparation(winner); e == nil || !bytes.Equal(stable, slot.read()) {
		t.Fatal("closed account resurrected", e)
	}
}
func TestMobileDAGRecoveredAggregateSizeBound(t *testing.T) {
	_, w, _, p, _, slot := b3MobileFixture(t)
	s, _ := w.newDAGPreparationStore()
	if e := s.SaveRecoveredPreparation(b3Intent(p)); e != nil {
		t.Fatal(e)
	}
	before := slot.read()
	candidate := clone(w.state)
	candidate.WriteJournal = make([]byte, 8<<20)
	w.mu.Lock()
	e := w.saveDAGCandidateLocked(candidate)
	w.mu.Unlock()
	if !errors.Is(e, ErrDAGProtectedState) || !bytes.Equal(before, slot.read()) {
		t.Fatal("whole-state size bypass", e)
	}
}
