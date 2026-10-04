package mobileworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 完整公开 DAG 合成图中的合法历史 receiver 与签 none：先验证来源，
// 再验证持久下界/封装门，不能把缺签源拒绝误计成修复。
func TestDAGEnvironmentReceiverHistorySurvivesMismatchAndCold(t *testing.T) {
	cfg, owner, slot, _ := dagBusinessAppliedFixture(t)
	defer owner.Close()
	var proof cryptox.IssuerRecoveryDAG
	if e := json.Unmarshal(owner.engine.State().Cloud.IssuerEvidence, &proof); e != nil {
		t.Fatal(e)
	}
	own := owner.state.Grants[0]
	if proof.Source.View == nil {
		t.Fatal("synthetic verified proof3 view missing")
	}
	targets := []cryptox.IssuerTarget{}
	for _, target := range proof.Source.View.Targets {
		if target.EnvironmentID == own.Grant.EnvironmentID {
			targets = append(targets, target)
		}
	}
	proof.Source.View.Targets = targets // 控制投影只含本次环境的唯一 own target。
	var other cryptox.SignedGrantWire
	if proof.Source.View == nil {
		t.Fatal("synthetic verified proof3 view missing")
	}
	for _, row := range proof.Source.View.Authorities {
		g := row.Grant
		if g.Grant.EnvironmentID == own.Grant.EnvironmentID && g.Grant.KeyVersion == own.Grant.KeyVersion && g.Grant.SubjectDeviceID != own.Grant.SubjectDeviceID {
			other = g
			break
		}
	}
	if other.Grant.SubjectDeviceID == "" {
		t.Fatal("synthetic historical receiver missing")
	}
	rows := []syncclient.ManagementSubject{}
	for _, signed := range []cryptox.SignedGrantWire{own, other} {
		g := signed
		rows = append(rows, syncclient.ManagementSubject{DeviceID: g.Grant.SubjectDeviceID, SigningPublicKey: g.Grant.SubjectSigningPublicKey, ReceivingPublicKey: g.Grant.SubjectReceivingPublicKey, CurrentGrant: &g, HighestGrantGeneration: g.Grant.GrantGeneration})
	}
	management := syncclient.ManagementControl{AccountID: owner.state.AccountID, AccountGeneration: owner.state.AccountGeneration, EnvironmentID: own.Grant.EnvironmentID, Sequence: owner.engine.State().Cloud.Sequence, KeyVersion: own.Grant.KeyVersion, Subjects: rows, IssuerDAGEvidence: &proof}
	control := syncclient.EnvironmentControlView{Sequence: management.Sequence, Grants: []cryptox.SignedGrantWire{own, other}, IssuerDAGEvidence: &proof}
	grant := other.Grant
	n, e := strconv.ParseUint(grant.GrantGeneration, 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	grant.IssuerDeviceID, grant.GrantGeneration = owner.state.DeviceID, strconv.FormatUint(n+1, 10)
	grant.Role, grant.Envelope, grant.IdempotencyKey, grant.ExpiresAt = "none", "", "synthetic-receiver-none", own.Grant.ExpiresAt
	signedNone, e := cryptox.SignGrant(grant, owner.signing)
	if e != nil {
		t.Fatal(e)
	}
	none := cryptox.GrantToWire(signedNone)
	latest := clone(management)
	latest.Subjects[1].CurrentGrant = &none
	latest.Subjects[1].HighestGrantGeneration = none.Grant.GrantGeneration
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")
		if request.Method == "POST" {
			posts.Add(1)
			w.WriteHeader(500)
			return
		}
		if strings.HasSuffix(request.URL.Path, "/grant-management") {
			_ = json.NewEncoder(w).Encode(map[string]any{"accountId": latest.AccountID, "accountGeneration": latest.AccountGeneration, "environmentId": latest.EnvironmentID, "sequence": latest.Sequence, "keyVersion": latest.KeyVersion, "subjects": latest.Subjects, "issuerEvidence": latest.IssuerDAGEvidence})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"sequence": control.Sequence, "grants": control.Grants, "issuerEvidence": control.IssuerDAGEvidence})
		}
	}))
	defer server.Close()
	dagBusinessRebindEndpoint(t, owner, &cfg, server.URL)
	owner.http = server.Client()
	state := clone(owner.state)
	state.DAGEnvironments = &dagEnvironmentJournal{Version: 1, Profile: cryptox.RecoveryDAGCapability, EnrollmentID: owner.state.RecoveredDAGDevice.Original.DeviceID, Records: map[string]*dagEnvironmentRecord{}, ReceiverControls: []syncclient.ManagementControl{}}
	p, e := owner.recoveredDAGOriginalLocked(owner.state.RecoveredDAGDevice.Original)
	if e != nil {
		t.Fatal(e)
	}
	state.DAGEnvironments.EnrollmentID, state.DAGEnvironments.EnrollmentHash = p.OperationID, p.ContentHash
	candidate := &Workflow{state: state, signing: bytes.Clone(owner.signing), receiving: bytes.Clone(owner.receiving), http: server.Client(), now: owner.now}
	defer clear(candidate.signing)
	defer clear(candidate.receiving)
	candidate.store = &memoryStore{state: clone(state.Cloud)}
	candidate.engine, e = localstate.New(candidate.store)
	if e != nil {
		t.Fatal(e)
	}
	candidate.verifier, e = candidate.recoveredDAGVerifierLocked()
	if e != nil {
		t.Fatal(e)
	}
	defer candidate.verifier.Close()
	gen, _ := strconv.ParseUint(state.AccountGeneration, 10, 64)
	candidate.client, e = syncclient.New(syncclient.Config{Endpoint: state.Endpoint, ProtocolMajor: 2, HTTPClient: server.Client(), AccountID: state.AccountID, AccountGeneration: gen, DeviceID: state.DeviceID, Token: cryptox.EncodeBase64(make([]byte, 32)), Verifier: candidate.verifier, Engine: candidate.engine, Now: candidate.now})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = candidate.client.VerifyEnvironmentControl(control, management.EnvironmentID); e != nil {
		t.Fatal("old receiver signature/source must first be valid", e)
	}
	if _, e = candidate.client.VerifyManagementControl(management); e != nil {
		t.Fatal("original management source must be valid", e)
	}
	if _, e = candidate.client.VerifyManagementControl(latest); e != nil {
		t.Fatal("higher signed none must be valid", e)
	}
	commit := &dagActiveWriteLog{owner: owner, candidate: candidate, ctx: context.Background(), hash: owner.protectedSHA256, epoch: owner.engine.State().SessionEpoch}
	if record, e := candidate.prepareDAGEnvironment(commit.ctx, "rotate", management.EnvironmentID, management.EnvironmentID, "", "synthetic-receiver-rotate", strings.Repeat("a", 64), commit); !errors.Is(e, syncclient.ErrWriteConflict) || record != nil || posts.Load() != 0 {
		t.Fatal("old receiver generated a packet or POST", e)
	}
	if len(owner.state.DAGEnvironments.Records) != 0 || len(owner.state.DAGEnvironments.ReceiverControls) != 1 || owner.state.Management != nil {
		t.Fatal("mismatch forgot verified none or promoted ordinary management")
	}
	cfg.ProtectedState = slot.read()
	cold, e := New(cfg)
	if e != nil {
		t.Fatal("history-only cold state", e)
	}
	defer cold.Close()
	if pending, e := cold.PendingDAGEnvironments(); e != nil || len(pending) != 0 {
		t.Fatal("history-only pending", e)
	}
	historyClient, close, e := cold.dagEnvironmentHistoryClient()
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	bounds, e := cold.verifyDAGReceiverHistory(historyClient)
	if e != nil {
		t.Fatal(e)
	}
	omitted := clone(latest)
	omitted.Sequence++
	omitted.Subjects = omitted.Subjects[:1]
	if _, e = historyClient.VerifyManagementControl(omitted, true); e != nil {
		t.Fatal("legal archived identity omission", e)
	}
	if e = bounds.remember(omitted); e != nil {
		t.Fatal(e)
	}
	rollback := clone(management)
	rollback.Sequence = omitted.Sequence
	if _, e = historyClient.VerifyManagementControl(rollback, true); e != nil {
		t.Fatal("old signed receiver must remain valid historical source", e)
	}
	if e = bounds.remember(rollback); !errors.Is(e, syncclient.ErrGrantUpdateConflict) {
		t.Fatal("omission cleared seen none generation", e)
	}
	changed := clone(latest)
	changed.Sequence = omitted.Sequence
	g := none.Grant
	g.IdempotencyKey = "synthetic-same-generation-different"
	s, e := cryptox.SignGrant(g, owner.signing)
	if e != nil {
		t.Fatal(e)
	}
	row := cryptox.GrantToWire(s)
	changed.Subjects[1].CurrentGrant = &row
	if _, e = historyClient.VerifyManagementControl(changed, true); e != nil {
		t.Fatal("same GG signed candidate must pass source verification", e)
	}
	if e = bounds.remember(changed); !errors.Is(e, syncclient.ErrGrantUpdateConflict) {
		t.Fatal("same generation changed signed fingerprint", e)
	}
	// unknown 原包再提交必须先通过同一管理门；不重新生成 ID/封套。
	if e = candidate.verifyAndCommitDAGReceivers(commit.ctx, control, management.EnvironmentID, commit, control); !errors.Is(e, syncclient.ErrWriteConflict) || posts.Load() != 0 {
		t.Fatal("unknown retry bypassed receiver gate", e)
	}
}

func TestDAGEnvironmentReceiverPersistenceFailureExactBasis(t *testing.T) {
	for _, exact := range []bool{true, false} {
		t.Run(map[bool]string{true: "captured", false: "native-advanced"}[exact], func(t *testing.T) {
			store := &memoryStore{state: localstate.EmptyState()}
			engine, e := localstate.New(store)
			if e != nil {
				t.Fatal(e)
			}
			owner := &Workflow{engine: engine, protectedSHA256: strings.Repeat("a", 64), checkNativeState: func(string) error {
				if !exact {
					return ErrDAGProtectedState
				}
				return nil
			}}
			commit := &dagActiveWriteLog{owner: owner, hash: owner.protectedSHA256, epoch: engine.State().SessionEpoch}
			cause := errors.New("synthetic persistence unavailable")
			e = receiverPersistenceFailure(commit, cause)
			if !errors.Is(e, cause) || errors.Is(e, ErrDAGAuthorizationNotPersisted) != exact || !owner.dagPersistenceFailed {
				t.Fatal("failure lost scope or requested deletion of advanced native version", e)
			}
		})
	}
}
