package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

func recoveredApprovalRecord(t *testing.T, w *Workflow, p syncclient.Pull) *approvalRecordV5 {
	t.Helper()
	child := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{122}, 32))
	recv := selfMust(ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{123}, 32)))
	now := w.now().Unix()
	c := cryptox.EnrollmentContext{Purpose: "enroll-device", AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, SessionID: "dag-approval-session", ChallengeNonce: cryptox.EncodeBase64(bytes.Repeat([]byte{124}, 32)), ExpiresAt: strconv.FormatInt(now+120, 10), InitiatorDeviceID: "dag-approval-child", InitiatorSigningPublicKey: cryptox.EncodeBase64(child.Public().(ed25519.PublicKey)), InitiatorReceivingPublicKey: cryptox.EncodeBase64(recv.PublicKey().Bytes()), ApproverDeviceID: w.state.DeviceID, ApproverSigningPublicKey: w.state.SigningPublicKey, ApproverReceivingPublicKey: w.state.ReceivingPublicKey}
	a := cryptox.EnrollmentApprovalV5{CertificateVersion: "5", Capabilities: []string{cryptox.RecoveryDAGCapability}, Context: c, PairingProfile: cryptox.EnrollmentPairingProfile, TranscriptHash: strings.Repeat("a", 64), IssuerProof: *p.IssuerDAGEvidence, Grants: []cryptox.SignedGrantWire{}}
	for _, parent := range p.Grants {
		g := parent.Grant
		g.IssuerDeviceID = c.ApproverDeviceID
		g.SubjectDeviceID = c.InitiatorDeviceID
		g.SubjectSigningPublicKey = c.InitiatorSigningPublicKey
		g.SubjectReceivingPublicKey = c.InitiatorReceivingPublicKey
		g.GrantGeneration = "1"
		g.Role = "ro"
		g.IdempotencyKey = "dag-approval-" + g.EnvironmentID
		a.Grants = append(a.Grants, cryptox.GrantToWire(selfMust(cryptox.SignGrant(g, w.signing))))
	}
	a.ApproverSignature = selfMust(cryptox.SignEnrollmentCertificateV5(selfMust(a.Certificate()), w.signing))
	r := &approvalRecordV5{Version: 1, SessionEpoch: w.engine.State().SessionEpoch, SessionID: c.SessionID, PairingID: "dag-approval-pair", CreatedAt: now, LastObservedAt: now, Approval: a}
	r.ChoicesHash = selfMust(choicesHash(r.PairingID, approvalSelectionsV5(r)))
	if err := w.validateApprovalV5(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRecoveredDAGApprovalJournalSurvivesRepeatedSaveAndColdRestart(t *testing.T) {
	cfg, w, slot, p := dagBusinessAppliedFixture(t)
	defer w.Close()
	r := recoveredApprovalRecord(t, w, p)
	w.state.PendingApprovalV5 = r
	if err := w.persist(); err != nil {
		t.Fatal(err)
	}
	r.Attempted = true
	if err := w.persist(); err != nil {
		t.Fatal(err)
	}
	cfg.ProtectedState = slot.read()
	cold, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	info, err := cold.ApprovalInfoV5()
	if err != nil || info.State != "unknown" || info.PairingID != r.PairingID {
		t.Fatal("lost attempted approval", info, err)
	}
	if err = cold.CancelApprovalV5(r.PairingID); !errors.Is(err, ErrApprovalPending) {
		t.Fatal("attempted approval discarded", err)
	}
	if _, err = cold.SetDAGVariable(context.Background(), "X", "SYNTHETIC", "value", "blocked-write"); !errors.Is(err, ErrApprovalPending) {
		t.Fatal("concurrent business accepted", err)
	}
	changed := clone(cold.state)
	changed.PendingApprovalV5.Approval.Grants[0].Grant.Role = "admin"
	cfg.ProtectedState = selfMust(json.Marshal(changed))
	if restored, err := New(cfg); err == nil {
		restored.Close()
		t.Fatal("tampered approval accepted")
	}
}

func TestRecoveredDAGApprovalSaveFailureClosesFurtherOperations(t *testing.T) {
	_, w, _, p := dagBusinessAppliedFixture(t)
	defer w.Close()
	w.state.PendingApprovalV5 = recoveredApprovalRecord(t, w, p)
	w.saveNativeCAS = func(string, []byte) error { return errors.New("synthetic persistence failure") }
	if err := w.persist(); !errors.Is(err, ErrDAGPersistence) {
		t.Fatal(err)
	}
	if _, err := w.ApprovalInfoV5(); !errors.Is(err, ErrDAGPersistence) {
		t.Fatal("failed save retained authority", err)
	}
}

func TestRecoveredDAGApprovalRefreshRevocationDropsLabelsBeforeCAS(t *testing.T) {
	cfg, w, slot, pull := dagBusinessAppliedFixture(t)
	defer w.Close()
	env := pull.Grants[0].Grant.EnvironmentID
	w.state.Labels[env] = labelState{Name: "synthetic-name", KeyVersion: pull.Grants[0].Grant.KeyVersion, Sequence: pull.Sequence}
	if err := w.persist(); err != nil {
		t.Fatal(err)
	}
	revoked := dagBusinessNone(t, w, pull)
	server := dagBusinessTLSServer(t, w, func(_ *http.Request, out http.ResponseWriter) { dagBusinessResponse(out, revoked) })
	defer server.Close()
	dagBusinessRebindEndpoint(t, w, &cfg, server.URL)
	w.http = server.Client()
	if err := w.refreshForApproval(context.Background()); err != nil {
		t.Fatal("approval refresh after revocation", err)
	}
	cfg.ProtectedState = slot.read()
	cold, err := New(cfg)
	if err != nil {
		t.Fatal("saved revoked source cannot reopen", err)
	}
	defer cold.Close()
	view, err := cold.RestoreDAGRecoveredDevice()
	if err != nil || len(view.View.Environments) != 0 || len(cold.state.Labels) != 0 {
		t.Fatal("revoked environment or label retained", err)
	}
}
