package mobileworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func b2Preparation(t *testing.T, original syncclient.ProtectedDAGOperation) syncclient.DAGTransitionPreparation {
	t.Helper()
	x := original.Transition.Submission.Transition
	initial, err := original.Transition.DependencyBundle.Initialization.Hash()
	if err != nil {
		t.Fatal(err)
	}
	seq, _ := strconv.ParseUint(x.ExpectedSequence, 10, 64)
	expires, _ := strconv.ParseInt(x.ExpiresAt, 10, 64)
	challenge := syncclient.DAGTransitionChallenge{OperationID: x.OperationID, ChallengeID: x.ChallengeID, Nonce: x.Nonce, ExpiresAt: expires, SessionHash: x.SessionHash, AccountGeneration: x.AccountGeneration, AuthorizationKind: x.AuthorizationKind, AuthorizerDeviceID: x.AuthorizerDeviceID, ExpectedSequence: x.ExpectedSequence, PreviousTransitionHash: x.PreviousTransitionHash, OldRecoveryGeneration: x.OldRecoveryGeneration, OldRecoverySigningPublicKey: x.OldRecoverySigningPublicKey, OldRecoveryReceivingPublicKey: x.OldRecoveryReceivingPublicKey, EnvironmentManifest: original.Transition.Submission.EnvironmentManifest, AuthoritySet: []cryptox.RecoveryAdminAuthority{}, DependencyBundle: original.Transition.DependencyBundle}
	p := syncclient.DAGTransitionPreparation{Version: 1, Kind: original.Kind, AuthorizationKind: x.AuthorizationKind, Phase: "prepared", Endpoint: original.Endpoint, AccountID: original.AccountID, AccountGeneration: original.AccountGeneration, Pin: original.Pin, InitializationHash: initial, InitializationProposalHash: original.Transition.DependencyBundle.Initialization.Proof.ProposalHash, SessionHash: x.SessionHash, OperationID: x.OperationID, ExpectedSequence: seq, OldRecoveryGeneration: x.OldRecoveryGeneration, PreviousTransitionHash: x.PreviousTransitionHash, OldRecoverySigningPublicKey: x.OldRecoverySigningPublicKey, OldRecoveryReceivingPublicKey: x.OldRecoveryReceivingPublicKey, BaseBundle: original.Transition.DependencyBundle, EnvironmentManifest: original.Transition.Submission.EnvironmentManifest, Challenge: &challenge, NewRecoveryGeneration: x.NewRecoveryGeneration, NewSigningPublicKey: x.NewRecoverySigningPublicKey, NewReceivingPublicKey: x.NewRecoveryReceivingPublicKey}
	if err = syncclient.ValidateDAGTransitionPreparation(p); err != nil {
		t.Fatal("valid public preparation prerequisite", err)
	}
	return p
}
func b2Intent(p syncclient.DAGTransitionPreparation) syncclient.DAGTransitionPreparation {
	p.Phase = "intent"
	p.Challenge = nil
	p.NewRecoveryGeneration = ""
	p.NewSigningPublicKey = ""
	p.NewReceivingPublicKey = ""
	return p
}

func TestMobileDAGPreparationAtomicPromotionAndColdInterruption(t *testing.T) {
	c, w, j, original, slot := b2MobileFixture(t)
	store, err := w.newDAGPreparationStore()
	if err != nil {
		t.Fatal(err)
	}
	prepared := b2Preparation(t, original)
	if err = store.SaveTransitionPreparation(b2Intent(prepared)); err != nil {
		t.Fatal(err)
	}
	intentBytes := slot.read()
	c.ProtectedState = intentBytes
	cold, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	meta, err := cold.RecoveryDAGPreparationInfo()
	if err != nil || meta.Phase != "intent" || meta.OperationID != original.OperationID || !meta.NeedsOriginalOwner || meta.TrustedDevice {
		t.Fatal("cold intent identity", err)
	}
	if _, err = cold.RecoveryDAGPendingInfo(); !errors.Is(err, ErrDAGPreparationInterrupted) {
		t.Fatal("prepare was treated as sealed or none", err)
	}
	if _, err = cold.View(); err == nil {
		t.Fatal("ordinary view entered pending preparation")
	}
	if err = store.SaveTransitionPreparation(prepared); err != nil {
		t.Fatal(err)
	}
	before := slot.read()
	if bytes.Equal(before, intentBytes) {
		t.Fatal("prepared was not durable")
	}
	if err = j.Save(original); err != nil {
		t.Fatal("single CAS promotion", err)
	}
	if w.state.RecoveryDAGPreparation != nil || w.state.RecoveryDAG == nil {
		t.Fatal("promotion left both/none")
	}
	c.ProtectedState = slot.read()
	reopen, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopen.Close()
	got, err := reopen.RecoveryDAGPendingInfo()
	if err != nil || got.OperationID != original.OperationID || got.TrustedDevice || got.OriginalApplied {
		t.Fatal("cold sealed original", err)
	}
	if _, err = store.LoadTransitionPreparation(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("prepared residue", err)
	}
}
func TestMobileDAGPreparationCASFailuresDoNotAdvance(t *testing.T) {
	for _, phase := range []string{"intent", "prepared", "sealed"} {
		t.Run(phase, func(t *testing.T) {
			c, w, j, original, slot := b2MobileFixture(t)
			store, err := w.newDAGPreparationStore()
			if err != nil {
				t.Fatal(err)
			}
			p := b2Preparation(t, original)
			if phase != "intent" {
				if err = store.SaveTransitionPreparation(b2Intent(p)); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "sealed" {
				if err = store.SaveTransitionPreparation(p); err != nil {
					t.Fatal(err)
				}
			}
			before := slot.read()
			ram := clone(w.state)
			var invalidated atomic.Int32
			w.dagOwnerCancel = func() { invalidated.Add(1) }
			slot.fail = true
			if phase == "sealed" {
				err = j.Save(original)
			} else if phase == "prepared" {
				err = store.SaveTransitionPreparation(p)
			} else {
				err = store.SaveTransitionPreparation(b2Intent(p))
			}
			if !errors.Is(err, ErrDAGPersistence) || invalidated.Load() != 1 || !bytes.Equal(before, slot.read()) {
				t.Fatal("CAS error failed immediate invalidation/atomicity", err)
			}
			a, _ := json.Marshal(w.state)
			b, _ := json.Marshal(ram)
			if !bytes.Equal(a, b) {
				t.Fatal("failed CAS advanced RAM")
			}
			if _, err = store.LoadTransitionPreparation(); !errors.Is(err, ErrDAGPersistence) {
				t.Fatal("failed owner remained valid", err)
			}
			slot.fail = false
			w.Close()
			if len(before) > 0 {
				c.ProtectedState = before
				reopen, err := New(c)
				if err != nil {
					t.Fatal(err)
				}
				defer reopen.Close()
				info, err := reopen.RecoveryDAGPreparationInfo()
				if err != nil || info.Phase != map[string]string{"prepared": "intent", "sealed": "prepared"}[phase] {
					t.Fatal("reopen invented next stage", err)
				}
			}
		})
	}
}
func TestMobileDAGPreparationImmutableIntentAndSchema(t *testing.T) {
	c, w, _, original, slot := b2MobileFixture(t)
	store, _ := w.newDAGPreparationStore()
	p := b2Preparation(t, original)
	intent := b2Intent(p)
	if err := store.SaveTransitionPreparation(intent); err != nil {
		t.Fatal(err)
	}
	stable := slot.read()
	for _, change := range []func(*syncclient.DAGTransitionPreparation){func(x *syncclient.DAGTransitionPreparation) { x.OperationID = "new-valid-id" }, func(x *syncclient.DAGTransitionPreparation) { x.ExpectedSequence++ }, func(x *syncclient.DAGTransitionPreparation) { x.SessionHash = strings.Repeat("b", 64) }} {
		copy := intent
		change(&copy)
		if err := syncclient.ValidateDAGTransitionPreparation(copy); err != nil {
			t.Fatal("valid alternative prerequisite", err)
		}
		if err := store.SaveTransitionPreparation(copy); !errors.Is(err, syncclient.ErrDAGPreparationConflict) || !bytes.Equal(stable, slot.read()) {
			t.Fatal("intent replaced", err)
		}
	}
	originalState := clone(w.state)
	for name, edit := range map[string]func(*protectedState){
		"epoch": func(x *protectedState) { x.RecoveryDAGPreparation.OwnerEpoch++ }, "account": func(x *protectedState) { x.RecoveryDAGPreparation.AccountID = "other-account" }, "device": func(x *protectedState) { x.RecoveryDAGPreparation.DeviceID = "other-device" }, "key": func(x *protectedState) { x.RecoveryDAGPreparation.SigningPublicKey = x.ReceivingPublicKey }, "closed": func(x *protectedState) { x.Cloud.AccountClosed = true }, "record-old-identity": func(x *protectedState) {
			changed := intent
			changed.OldRecoverySigningPublicKey = p.NewSigningPublicKey
			x.RecoveryDAGPreparation.Record, _ = json.Marshal(changed)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clone(originalState)
			edit(&candidate)
			raw, _ := json.Marshal(candidate)
			if err := slot.save(raw); err != nil {
				t.Fatal(err)
			}
			if err := slot.check(protectedStateHash(raw)); err != nil {
				t.Fatal("target validator must receive matching native snapshot", err)
			}
			c.ProtectedState = raw
			reopened, err := New(c)
			if err == nil {
				reopened.Close()
				t.Fatal("mixed preparation schema accepted")
			}
		})
	}
}
func TestMobileDAGPreparationLogoutCannotBeResurrected(t *testing.T) {
	_, w, _, original, slot := b2MobileFixture(t)
	store, _ := w.newDAGPreparationStore()
	p := b2Intent(b2Preparation(t, original))
	if err := store.SaveTransitionPreparation(p); err != nil {
		t.Fatal(err)
	}
	if err := w.Logout(); err != nil {
		t.Fatal(err)
	}
	stable := slot.read()
	if w.state.RecoveryDAGPreparation != nil || w.state.RecoveryDAG != nil || !w.engine.State().AccountClosed {
		t.Fatal("logout retained preparation")
	}
	if err := store.SaveTransitionPreparation(p); err == nil || !bytes.Equal(stable, slot.read()) {
		t.Fatal("old owner resurrected closed account")
	}
}
func TestMobileDAGPreparationPredecessorRequiresAppliedExactOriginal(t *testing.T) {
	_, w, j, original, _ := b2MobileFixture(t)
	store, _ := w.newDAGPreparationStore()
	p := b2Intent(b2Preparation(t, original))
	p.OperationID = "next-transition"
	if err := j.Save(original); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTransitionPreparation(p); err == nil {
		t.Fatal("pending original overwritten by prepare")
	}
	expected, _ := strconv.ParseUint(original.Transition.Submission.Transition.ExpectedSequence, 10, 64)
	original.Applied = true
	original.AcceptedSequence = expected + 1
	if err := j.Save(original); err != nil {
		t.Fatal(err)
	}
	// Context boundary tested separately using valid old proof and explicit predecessor.
	p.BaseBundle.Records = append(p.BaseBundle.Records, cryptox.RecoveryDAGRecord{Kind: "transition-v2", TransitionV2: &cryptox.AcceptedRecoveryTransitionV2{Sequence: original.AcceptedSequence, Submission: original.Transition.Submission}})
	p.PreviousTransitionHash = original.ContentHash
	p.OldRecoveryGeneration = original.Transition.Submission.Transition.NewRecoveryGeneration
	p.OldRecoverySigningPublicKey = original.Transition.Submission.Transition.NewRecoverySigningPublicKey
	p.OldRecoveryReceivingPublicKey = original.Transition.Submission.Transition.NewRecoveryReceivingPublicKey
	p.ExpectedSequence = original.AcceptedSequence
	p.PriorOperationID = original.OperationID
	p.PriorContentHash = original.ContentHash
	p.PriorAcceptedSequence = original.AcceptedSequence
	if err := syncclient.ValidateDAGTransitionPreparation(p); err != nil {
		t.Fatal("valid preparation prerequisite", err)
	}
	if err := store.SaveTransitionPreparation(p); err != nil {
		t.Fatal("explicit applied predecessor rejected", err)
	}
}
func TestMobileDAGTransitionCompleteCodePreflightClearsInput(t *testing.T) {
	_, w, _, _, _ := b2MobileFixture(t)
	code := []byte("incomplete")
	_, err := w.SealDAGRecoveryTransition(context.Background(), nil, DAGOwnerScope{}, code)
	if !errors.Is(err, syncclient.ErrDAGNewCodeMismatch) || !bytes.Equal(code, make([]byte, len(code))) {
		t.Fatal("format reentry did not fail before owner acquisition/clear", err)
	}
}
func b2Original(t *testing.T, p syncclient.ProtectedDAGOperation) syncclient.ProtectedDAGOperation {
	t.Helper()
	raw, err := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public vector")
	}
	sub := f.Proof.Records[2].TransitionV2.Submission
	p.OperationID = sub.Transition.OperationID
	p.ContentHash, err = cryptox.RecoveryTransitionHashV2(sub)
	if err != nil {
		t.Fatal(err)
	}
	p.Transition = &cryptox.RecoveryTransitionCommandV2{Submission: sub, DependencyBundle: cryptox.RecoveryDependencyBundle{Initialization: f.Proof.Initialization, Records: f.Proof.Records[:2]}}
	return p
}
func b2MobileFixture(t *testing.T) (Config, *Workflow, *syncclient.CheckedDAGJournal, syncclient.ProtectedDAGOperation, *dagNativeSlot) {
	c, w, j, p, s := dagMobileFixture(t)
	return c, w, j, b2Original(t, p), s
}

func TestMobileDAGPreparationConcurrentOwnersCannotOverwriteWinner(t *testing.T) {
	c, w, _, original, slot := b2MobileFixture(t)
	store, _ := w.newDAGPreparationStore()
	p := b2Preparation(t, original)
	if err := store.SaveTransitionPreparation(b2Intent(p)); err != nil {
		t.Fatal(err)
	}
	c.ProtectedState = slot.read()
	other, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherStore, _ := other.newDAGPreparationStore()
	first := clone(p)
	winner := clone(p)
	winner.NewSigningPublicKey = cryptox.EncodeBase64(bytes.Repeat([]byte{9}, 32))
	if err := syncclient.ValidateDAGTransitionPreparation(winner); err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	slot.entered, slot.resume = entered, resume
	result := make(chan error, 1)
	go func() { result <- store.SaveTransitionPreparation(first) }()
	<-entered
	if err = otherStore.SaveTransitionPreparation(winner); err != nil {
		t.Fatal(err)
	}
	stable := slot.read()
	close(resume)
	if err = <-result; !errors.Is(err, syncclient.ErrDAGJournalConflict) || !bytes.Equal(stable, slot.read()) {
		t.Fatal("stale authenticated Workflow overwrote winner", err)
	}
	c.ProtectedState = stable
	reopen, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopen.Close()
	loaded, _ := reopen.newDAGPreparationStore()
	got, err := loaded.LoadTransitionPreparation()
	if err != nil || got.NewSigningPublicKey != winner.NewSigningPublicKey {
		t.Fatal("winner not durable", err)
	}
}
func TestMobileDAGPreparationAggregateSizeBound(t *testing.T) {
	_, w, _, original, slot := b2MobileFixture(t)
	store, _ := w.newDAGPreparationStore()
	if err := store.SaveTransitionPreparation(b2Intent(b2Preparation(t, original))); err != nil {
		t.Fatal(err)
	}
	stable := slot.read()
	candidate := clone(w.state)
	candidate.WriteJournal = bytes.Repeat([]byte{0}, 8<<20)
	w.mu.Lock()
	err := w.saveDAGCandidateLocked(candidate)
	w.mu.Unlock()
	if !errors.Is(err, ErrDAGProtectedState) || !bytes.Equal(stable, slot.read()) {
		t.Fatal("nested additions bypassed whole-state 8 MiB limit", err)
	}
}
