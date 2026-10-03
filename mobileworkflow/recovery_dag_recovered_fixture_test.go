package mobileworkflow

import (
	"encoding/json"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/internal/dagrecoveredfixture"
	"github.com/harmonia-vault/core-go/syncclient"
	"strconv"
	"testing"
)

func b3Preparation(t *testing.T, f dagrecoveredfixture.Fixture, endpoint string) (syncclient.DAGRecoveredPreparation, syncclient.ProtectedDAGOperation, syncclient.ProtectedDAGOperation) {
	t.Helper()
	sub := f.Submission
	e := sub.Enrollment
	gen, _ := strconv.ParseUint(f.Pin.AccountGeneration, 10, 64)
	seq, _ := strconv.ParseUint(e.ExpectedSequence, 10, 64)
	expiry, _ := strconv.ParseInt(e.ExpiresAt, 10, 64)
	hash, err := cryptox.RecoveredDeviceReferenceHashV2(sub)
	if err != nil {
		t.Fatal(err)
	}
	priorHash, err := cryptox.RecoveryTransitionHashV2(f.Prior.Submission)
	if err != nil {
		t.Fatal(err)
	}
	initHash, err := f.Bundle.Initialization.Hash()
	if err != nil {
		t.Fatal(err)
	}
	prior := syncclient.ProtectedDAGOperation{Version: 1, Endpoint: endpoint, AccountID: f.Pin.AccountID, AccountGeneration: gen, Pin: f.Pin, Kind: "transition-v2", OperationID: f.Prior.Submission.Transition.OperationID, ContentHash: priorHash, Transition: &cryptox.RecoveryTransitionCommandV2{Submission: f.Prior.Submission, DependencyBundle: cryptox.RecoveryDependencyBundle{Initialization: f.Bundle.Initialization, Records: f.Bundle.Records[:2]}}, Attempted: true, AcceptedSequence: f.Prior.Sequence, Applied: true}
	next := syncclient.ProtectedDAGOperation{Version: 1, Endpoint: endpoint, AccountID: f.Pin.AccountID, AccountGeneration: gen, Pin: f.Pin, Kind: "recovered-v2", OperationID: e.OperationID, ContentHash: hash, Recovered: &cryptox.RecoveredDeviceCommandV2{Submission: sub, DependencyBundle: f.Bundle}}
	p := syncclient.DAGRecoveredPreparation{Version: 1, Kind: "recovered-v2", Phase: "challenged", Endpoint: endpoint, AccountID: f.Pin.AccountID, AccountGeneration: gen, Pin: f.Pin, InitializationHash: initHash, InitializationProposalHash: f.Bundle.Initialization.Proof.ProposalHash, RestrictedSessionHash: e.RestrictedSessionHash, OperationID: e.OperationID, ExpectedSequence: seq, RecoveryGeneration: e.RecoveryGeneration, RecoveryHeadHash: e.RecoveryTransitionHash, RecoverySigningPublicKey: f.Prior.Submission.Transition.NewRecoverySigningPublicKey, RecoveryReceivingPublicKey: f.Prior.Submission.Transition.NewRecoveryReceivingPublicKey, DeviceID: e.DeviceID, DeviceSigningPublicKey: e.DeviceSigningPublicKey, DeviceReceivingPublicKey: e.DeviceReceivingPublicKey, BaseBundle: f.Bundle, EnvironmentManifest: f.Prior.Submission.EnvironmentManifest, SelectedRights: sub.SelectedRights, SelectedRightsHash: e.SelectedRightsHash, PriorOperationID: prior.OperationID, PriorContentHash: prior.ContentHash, PriorAcceptedSequence: prior.AcceptedSequence, Challenge: &syncclient.DAGDeviceChallenge{OperationID: e.OperationID, ChallengeID: e.ChallengeID, Nonce: e.Nonce, ExpiresAt: expiry, AccountGeneration: e.AccountGeneration, RestrictedSessionHash: e.RestrictedSessionHash, ExpectedSequence: e.ExpectedSequence, RecoveryGeneration: e.RecoveryGeneration, RecoveryTransitionHash: e.RecoveryTransitionHash, DeviceID: e.DeviceID, DeviceSigningPublicKey: e.DeviceSigningPublicKey, DeviceReceivingPublicKey: e.DeviceReceivingPublicKey, DependencyBundle: f.Bundle, IssuerEvidence: sub.IssuerEvidence}}
	raw, _ := json.Marshal(p)
	if _, err = syncclient.DecodeDAGRecoveredPreparation(raw); err != nil {
		t.Fatal("valid signed preparation prerequisite", err)
	}
	return p, prior, next
}
func b3Intent(p syncclient.DAGRecoveredPreparation) syncclient.DAGRecoveredPreparation {
	p.Phase = "intent"
	p.Challenge = nil
	return p
}

func b3MobileFixture(t *testing.T) (Config, *Workflow, *syncclient.CheckedDAGJournal, syncclient.DAGRecoveredPreparation, syncclient.ProtectedDAGOperation, *dagNativeSlot) {
	t.Helper()
	c, w, j, _, slot := dagMobileFixture(t)
	f := dagrecoveredfixture.Load(t, "../cryptox/testdata/recovery-dag-v1.json", w.state.DeviceID, c.SigningKey, c.ReceivingPrivateKey)
	p, prior, next := b3Preparation(t, f, c.Endpoint)
	fresh := prior
	fresh.Attempted = false
	fresh.AcceptedSequence = 0
	fresh.Applied = false
	if e := j.Save(fresh); e != nil {
		t.Fatal(e)
	}
	attempted := fresh
	attempted.Attempted = true
	if e := j.Save(attempted); e != nil {
		t.Fatal(e)
	}
	accepted := attempted
	accepted.AcceptedSequence = prior.AcceptedSequence
	if e := j.Save(accepted); e != nil {
		t.Fatal(e)
	}
	if e := j.Save(prior); e != nil {
		t.Fatal(e)
	}
	return c, w, j, p, next, slot
}
