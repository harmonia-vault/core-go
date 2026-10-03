package mobileworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
	"net"
	"net/http"
	"os"
	"testing"
)

func resolutionFixture(t *testing.T) (Config, *Workflow, *syncclient.CheckedDAGJournal, syncclient.ProtectedDAGOperation, *dagNativeSlot) {
	c, w, j, p, slot := dagMobileFixture(t)
	raw, e := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public fixture")
	}
	sub := f.Proof.Records[2].TransitionV2.Submission
	p.OperationID = sub.Transition.OperationID
	p.ContentHash, e = cryptox.RecoveryTransitionHashV2(sub)
	if e != nil {
		t.Fatal(e)
	}
	p.Transition = &cryptox.RecoveryTransitionCommandV2{Submission: sub, DependencyBundle: cryptox.RecoveryDependencyBundle{Initialization: f.Proof.Initialization, Records: f.Proof.Records[:2]}}
	if e = j.Save(p); e != nil {
		t.Fatal(e)
	}
	return c, w, j, p, slot
}
func resolutionPlanFixture(t *testing.T, w *Workflow, p syncclient.ProtectedDAGOperation) *recoveryDAGResolutionState {
	t.Helper()
	binding, e := w.dagBindingLocked()
	if e != nil {
		t.Fatal(e)
	}
	target, e := syncclient.RecoveryOperationTargetFromSealedTransition(binding, w.state.RecoveryDAG.Journal, w.state.DeviceID, w.state.SigningPublicKey, w.state.ReceivingPublicKey)
	if e != nil {
		t.Fatal(e)
	}
	h, _ := target.Hash()
	return &recoveryDAGResolutionState{Version: 1, Profile: cryptox.RecoveryOperationClosureCapability, Endpoint: binding.Endpoint, AccountID: binding.AccountID, AccountGeneration: binding.AccountGeneration, DeviceID: w.state.DeviceID, SigningPublicKey: w.state.SigningPublicKey, ReceivingPublicKey: w.state.ReceivingPublicKey, OwnerEpoch: binding.OwnerEpoch, Baseline: recoveryDAGResolutionBaseline{Pin: p.Pin, DependencyBundle: p.Transition.DependencyBundle, MinimumSequence: recoveryBundleSequence(p.Transition.DependencyBundle)}, Pending: &recoveryDAGResolutionPlan{Target: target, TargetHash: h, OriginalPublicDigest: target.DeclaredIntentHash, CloseRequested: true, CloseAttempted: true}, Closed: []recoveryDAGClosedEntry{}}
}
func resolutionClosedCandidate(t *testing.T, w *Workflow, r *recoveryDAGResolutionState) protectedState {
	t.Helper()
	candidate := clone(w.state)
	candidate.Cloud = w.engine.State()
	candidate.RecoveryDAGResolution = r
	candidate.DAGCASRequired = true
	plan := r.Pending
	known := plan.Target.KnownChallengeHash
	seq := uint64(0)
	_ = json.Unmarshal([]byte(plan.Target.Basis.ExpectedSequence), &seq)
	seq++
	receipt := cryptox.RecoveryOperationResolutionReceipt{Version: 1, Profile: cryptox.RecoveryOperationResolutionProfile, AccountID: r.AccountID, AccountGeneration: plan.Target.AccountGeneration, Kind: plan.Target.Kind, OperationID: plan.Target.OperationID, TargetHash: plan.TargetHash, State: "closed", Sequence: seq, ObservedChallengeHash: &known}
	r.Closed = append(r.Closed, recoveryDAGClosedEntry{Target: plan.Target, TargetHash: plan.TargetHash, Receipt: receipt, OriginalPublicDigest: plan.OriginalPublicDigest, OwnerEpoch: r.OwnerEpoch})
	r.Pending = nil
	r.Baseline.MinimumSequence = seq
	candidate.RecoveryDAG = nil
	return candidate
}
func TestDAGResolutionClosedAtomicHistoryAndExplicitNewGate(t *testing.T) {
	c, w, _, p, slot := resolutionFixture(t)
	r := resolutionPlanFixture(t, w, p)
	candidate := clone(w.state)
	candidate.Cloud = w.engine.State()
	candidate.RecoveryDAGResolution = r
	if e := w.saveDAGCandidateLocked(candidate); e != nil {
		t.Fatal(e)
	}
	before := slot.read()
	candidate = resolutionClosedCandidate(t, w, clone(w.state).RecoveryDAGResolution)
	slot.fail = true
	if e := w.saveDAGCandidateLocked(candidate); !errors.Is(e, ErrDAGPersistence) {
		t.Fatal("CAS failure missing", e)
	}
	if !bytes.Equal(before, slot.read()) || w.state.RecoveryDAG == nil || w.state.RecoveryDAGResolution.Pending == nil {
		t.Fatal("failed CAS cleared original")
	}
	w.Close()
	slot.fail = false
	c.ProtectedState = slot.read()
	cold, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer cold.Close()
	candidate = resolutionClosedCandidate(t, cold, clone(cold.state).RecoveryDAGResolution)
	if e = cold.saveDAGCandidateLocked(candidate); e != nil {
		t.Fatal(e)
	}
	after := slot.read()
	cold.Close()
	c.ProtectedState = after
	again, e := New(c)
	if e != nil {
		t.Fatal("closed cold validation", e)
	}
	defer again.Close()
	info, e := again.RecoveryDAGResolutionInfo()
	if e != nil || info.LocalState != "closed" || info.TrustedDevice || len(again.state.RecoveryDAGResolution.Baseline.DependencyBundle.Records) != 2 {
		t.Fatal("closed history or false trust", e)
	}
	reg, _ := NewDAGRecoveryRegistry(DAGOwnerScope{Namespace: "synthetic", Slot: "slot"})
	defer reg.Close()
	if _, e = again.OpenDAGRecoveryOwner(context.Background(), reg, DAGOwnerScope{Namespace: "synthetic", Slot: "slot"}, dagQueryCode(t)); !errors.Is(e, ErrDAGResolutionPending) {
		t.Fatal("ordinary opener silently reset checkpoint", e)
	}
	candidate = clone(again.state)
	candidate.Cloud = again.engine.State()
	candidate.RecoveryDAGResolution.Closed = nil
	if e = again.saveDAGCandidateLocked(candidate); e == nil {
		t.Fatal("closed receipt deletion accepted")
	}
	if e = again.Logout(); e != nil {
		t.Fatal(e)
	}
	if again.state.RecoveryDAGResolution == nil || len(again.state.RecoveryDAGResolution.Closed) != 1 || !again.requiresDAGCAS {
		t.Fatal("logout erased tombstone or CAS requirement")
	}
}
func TestDAGResolutionRejectedScopeAndUnsupportedHasNoNetwork(t *testing.T) {
	for _, mode := range []string{"all-admin", "no-original", "stale-native", "missing-CAS", "canceled", "wrong-target"} {
		t.Run(mode, func(t *testing.T) {
			_, w, _, _, slot := resolutionFixture(t)
			if mode == "all-admin" {
				w.Close()
				_, fresh, j, p, native := dagMobileFixture(t)
				w, slot = fresh, native
				if e := j.Save(p); e != nil {
					t.Fatal(e)
				}
			}
			defer w.Close()
			var dials int
			w.http = &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
				dials++
				return nil, errors.New("synthetic forbidden dial")
			}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "no-original":
				w.state.RecoveryDAG = nil
			case "stale-native":
				_ = slot.save([]byte("synthetic foreign snapshot"))
			case "missing-CAS":
				w.saveNativeCAS = nil
			case "canceled":
				cancel()
			}
			scope := DAGOwnerScope{Namespace: "synthetic", Slot: "slot"}
			r, _ := NewDAGRecoveryRegistry(scope)
			defer r.Close()
			code := dagQueryCode(t)
			expected := "invalid-hash"
			if mode != "all-admin" && mode != "no-original" && mode != "wrong-target" {
				if mode == "stale-native" || mode == "missing-CAS" {
					binding := syncclient.DAGJournalBinding{Endpoint: w.state.Endpoint, AccountID: w.state.AccountID, AccountGeneration: 1, OwnerEpoch: w.engine.State().SessionEpoch}
					target, err := syncclient.RecoveryOperationTargetFromSealedTransition(binding, w.state.RecoveryDAG.Journal, w.state.DeviceID, w.state.SigningPublicKey, w.state.ReceivingPublicKey)
					if err != nil {
						t.Fatal(err)
					}
					expected, _ = target.Hash()
				} else {
					info, err := w.RecoveryDAGResolutionInfo()
					if err != nil {
						t.Fatal(err)
					}
					expected = info.TargetHash
				}
			}
			out, e := w.CloseDAGOperationOriginal(ctx, r, scope, code, expected)
			if e == nil || out.TrustedDevice || dials != 0 || !bytes.Equal(code, make([]byte, len(code))) {
				t.Fatal("rejected scope opened network or retained code", e)
			}
			if mode == "stale-native" && (!w.closed || len(w.signing) != 0 || len(w.receiving) != 0) {
				t.Fatal("native stale preflight retained process keys")
			}
		})
	}
}
func TestDAGResolutionColdRejectsClosedIDReuseAndRollback(t *testing.T) {
	c, w, _, p, slot := resolutionFixture(t)
	r := resolutionPlanFixture(t, w, p)
	candidate := resolutionClosedCandidate(t, w, r)
	if e := w.saveDAGCandidateLocked(candidate); e != nil {
		t.Fatal(e)
	}
	original := syncclient.ProtectedDAGOperation{}
	raw, e := json.Marshal(struct {
		OwnerEpoch uint64                           `json:"ownerEpoch"`
		Operation  syncclient.ProtectedDAGOperation `json:"operation"`
	}{w.engine.State().SessionEpoch, p})
	_ = original
	if e != nil {
		t.Fatal(e)
	}
	base := slot.read()
	var state protectedState
	if decode(base, &state) != nil {
		t.Fatal("closed parse")
	}
	state.RecoveryDAG = &recoveryDAGState{Version: 1, Profile: cryptox.RecoveryDAGCapability, Endpoint: w.state.Endpoint, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, DeviceID: w.state.DeviceID, SigningPublicKey: w.state.SigningPublicKey, ReceivingPublicKey: w.state.ReceivingPublicKey, OwnerEpoch: 0, Journal: raw}
	bad, _ := json.Marshal(state)
	c.ProtectedState = bad
	slot.packet = bad
	if cold, e := New(c); e == nil {
		cold.Close()
		t.Fatal("closedID reopened as original")
	}
}

func TestDAGResolutionColdBaselineContainsAllRecordSequences(t *testing.T) {
	_, w, _, p, _ := resolutionFixture(t)
	defer w.Close()
	r := resolutionPlanFixture(t, w, p)
	candidate := clone(w.state)
	candidate.Cloud = w.engine.State()
	candidate.RecoveryDAGResolution = r
	if e := validateDAGResolutionState(candidate); e != nil {
		t.Fatal("legal baseline", e)
	}
	graph, e := cryptox.VerifyRecoveryDependencyBundle(r.Baseline.Pin, r.Baseline.DependencyBundle)
	if e != nil {
		t.Fatal(e)
	}
	head, e := graph.RecoveryCheckpoint()
	if e != nil {
		t.Fatal(e)
	}
	if head.AcceptedSequence >= recoveryBundleSequence(r.Baseline.DependencyBundle) {
		t.Fatal("fixture must have later accepted nonrotation")
	}
	r.Baseline.MinimumSequence = head.AcceptedSequence
	if e := validateDAGResolutionState(candidate); e == nil {
		t.Fatal("lower floor ignored recovered record")
	}
}

func TestDAGResolutionUnsupportedRecoveredAndPreparationsZeroNetwork(t *testing.T) {
	for _, phase := range []string{"intent", "challenged", "sealed"} {
		t.Run(phase, func(t *testing.T) {
			_, w, j, p, next, _ := b3MobileFixture(t)
			defer w.Close()
			store, e := w.newDAGPreparationStore()
			if e != nil {
				t.Fatal(e)
			}
			if phase != "sealed" {
				if e = store.SaveRecoveredPreparation(b3Intent(p)); e != nil {
					t.Fatal(e)
				}
				if phase == "challenged" {
					if e = store.SaveRecoveredPreparation(p); e != nil {
						t.Fatal(e)
					}
				}
			} else if e = j.Save(next); e != nil {
				t.Fatal(e)
			}
			var posts int
			w.http = &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
				posts++
				return nil, errors.New("synthetic forbidden network")
			}}}
			scope := DAGOwnerScope{Namespace: "synthetic", Slot: "unsupported"}
			r, _ := NewDAGRecoveryRegistry(scope)
			defer r.Close()
			_, e = w.QueryDAGOperationResolution(context.Background(), r, scope, dagQueryCode(t))
			if !errors.Is(e, syncclient.ErrRecoveryResolutionUnsupported) || posts != 0 {
				t.Fatal("unsupported highlevel reached network", e)
			}
		})
	}
}

func TestDAGResolutionColdRejectsClosedAcceptedHistoryContradiction(t *testing.T) {
	_, w, _, p, _ := resolutionFixture(t)
	defer w.Close()
	candidate := resolutionClosedCandidate(t, w, resolutionPlanFixture(t, w, p))
	r := candidate.RecoveryDAGResolution
	bundle := p.Transition.DependencyBundle
	accepted := cryptox.AcceptedRecoveryTransitionV2{Submission: p.Transition.Submission, Sequence: r.Closed[0].Receipt.Sequence}
	bundle.Records = append(bundle.Records, cryptox.RecoveryDAGRecord{Kind: "transition-v2", TransitionV2: &accepted})
	if _, e := cryptox.VerifyRecoveryDependencyBundle(p.Pin, bundle); e != nil {
		t.Fatal("must be otherwise valid accepted graph", e)
	}
	r.Baseline.DependencyBundle = bundle
	if e := validateDAGResolutionState(candidate); e == nil {
		t.Fatal("same operation both closed and accepted")
	}
}
