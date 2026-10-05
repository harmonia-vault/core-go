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

func TestDAGManagementOnlyExactSelfDowngradeException(t *testing.T) {
	err := &syncclient.RequestError{Status: 403, Code: "admin_required"}
	in := syncclient.GrantUpdateIntent{SubjectDeviceID: "synthetic-self"}
	current := localstate.Environment{Role: localstate.ReadOnly}
	if !dagSelfDowngradeReceiptException(in, "synthetic-self", current, true, err) {
		t.Fatal("exact verified self downgrade denied")
	}
	in.SubjectDeviceID = "synthetic-other"
	if dagSelfDowngradeReceiptException(in, "synthetic-self", current, true, err) {
		t.Fatal("other grant swallowed own concurrent downgrade")
	}
	in.SubjectDeviceID = "synthetic-self"
	if dagSelfDowngradeReceiptException(in, "synthetic-self", current, true, errors.Join(err, syncclient.ErrTrustInvalidated)) {
		t.Fatal("terminal trust swallowed")
	}
	if dagSelfDowngradeReceiptException(in, "synthetic-self", localstate.Environment{Role: localstate.Admin}, true, err) {
		t.Fatal("still Admin swallowed denial")
	}
}

// 原包/完整图先通过真实成熟验证，之后证明accepted但尚未Applied的none
// 限制所有共享receiver入口；不把缺来源拒绝算下界修复。
func TestDAGConfirmedGrantConstrainsSharedReceiversAndCold(t *testing.T) {
	cfg, w, slot, _ := dagBusinessAppliedFixture(t)
	defer w.Close()
	var proof cryptox.IssuerRecoveryDAG
	if e := json.Unmarshal(w.engine.State().Cloud.IssuerEvidence, &proof); e != nil {
		t.Fatal(e)
	}
	own := w.state.Grants[0]
	env := own.Grant.EnvironmentID
	selected := []cryptox.IssuerTarget{}
	for _, target := range proof.Source.View.Targets {
		if target.EnvironmentID == env {
			selected = append(selected, target)
		}
	}
	proof.Source.View.Targets = selected
	var other cryptox.SignedGrantWire
	for _, node := range proof.Source.View.Authorities {
		g := node.Grant
		if g.Grant.EnvironmentID == env && g.Grant.KeyVersion == own.Grant.KeyVersion && g.Grant.SubjectDeviceID != w.state.DeviceID {
			other = g
			break
		}
	}
	if other.Grant.SubjectDeviceID == "" {
		t.Fatal("synthetic archived target missing")
	}
	rows := []syncclient.ManagementSubject{}
	for _, g := range []cryptox.SignedGrantWire{own, other} {
		copy := g
		rows = append(rows, syncclient.ManagementSubject{DeviceID: g.Grant.SubjectDeviceID, SigningPublicKey: g.Grant.SubjectSigningPublicKey, ReceivingPublicKey: g.Grant.SubjectReceivingPublicKey, CurrentGrant: &copy, HighestGrantGeneration: g.Grant.GrantGeneration})
	}
	control := syncclient.ManagementControl{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, Sequence: w.engine.State().Cloud.Sequence, KeyVersion: own.Grant.KeyVersion, Subjects: rows, IssuerDAGEvidence: &proof}
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		out.Header().Set("Harmonia-Protocol-Major", "2")

		out.Header().Set("Harmonia-Protocol-Major", "2")
		if r.Method == "POST" {
			posts.Add(1)
			out.WriteHeader(500)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/grant-status") {
			_ = json.NewEncoder(out).Encode(syncclient.GrantStatus{IdempotencyKey: r.URL.Query().Get("idempotencyKey")})
			return
		}
		_ = json.NewEncoder(out).Encode(map[string]any{"accountId": control.AccountID, "accountGeneration": control.AccountGeneration, "environmentId": control.EnvironmentID, "sequence": control.Sequence, "keyVersion": control.KeyVersion, "subjects": control.Subjects, "issuerEvidence": control.IssuerDAGEvidence})
	}))
	defer server.Close()
	dagBusinessRebindEndpoint(t, w, &cfg, server.URL)
	v, e := w.recoveredDAGVerifierLocked()
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	gen, _ := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	c, e := syncclient.New(syncclient.Config{Endpoint: server.URL, ProtocolMajor: 2, HTTPClient: server.Client(), AccountID: w.state.AccountID, AccountGeneration: gen, DeviceID: w.state.DeviceID, Token: cryptox.EncodeBase64(make([]byte, 32)), Verifier: v, Engine: w.engine, Now: w.now})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.VerifyManagementControl(control); e != nil {
		t.Fatal("original source must be valid", e)
	}
	in := syncclient.GrantUpdateIntent{ID: "synthetic-confirmed-none", EnvironmentID: env, SubjectDeviceID: other.Grant.SubjectDeviceID, Role: "none"}
	tx, e := c.PrepareDAGGrantUpdate(context.Background(), in, w.signing, func(syncclient.ManagementControl) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	packet, e := tx.ProtectedBytes()
	if e != nil {
		t.Fatal(e)
	}
	hash, e := tx.ContentHash()
	if e != nil {
		t.Fatal(e)
	}
	p, e := w.recoveredDAGOriginalLocked(w.state.RecoveredDAGDevice.Original)
	if e != nil {
		t.Fatal(e)
	}
	w.state.DAGEnvironments = &dagEnvironmentJournal{Version: 1, Profile: cryptox.RecoveryDAGCapability, EnrollmentID: p.OperationID, EnrollmentHash: p.ContentHash, Records: map[string]*dagEnvironmentRecord{}, ReceiverControls: []syncclient.ManagementControl{control}}
	w.state.DAGManagement = &dagManagementJournal{Version: 1, Profile: cryptox.RecoveryDAGCapability, EnrollmentID: p.OperationID, EnrollmentHash: p.ContentHash, Records: map[string]*dagGrantRecord{in.ID: {Packet: packet, ContentHash: hash, Attempted: true, Sequence: control.Sequence + 1}}}
	if e = w.saveDAGCandidateLocked(clone(w.state)); e != nil {
		t.Fatal(e)
	}
	before := slot.read()
	// 来源仍合法；旧GG拒绝来自我们已确认原包的共享下界。
	control.Sequence++
	if _, e = c.VerifyManagementControl(control); e != nil {
		t.Fatal("replayed row must pass source first", e)
	}
	b, e := w.verifyDAGReceiverHistory(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.remember(control); !errors.Is(e, syncclient.ErrGrantUpdateConflict) {
		t.Fatal("accepted none was forgotten", e)
	}
	if got := b.subjects[env][other.Grant.SubjectDeviceID]; got.Generation != environmentValueForDAGManagement(t, tx.OriginalGrant().Grant.GrantGeneration) || got.Fingerprint != hash {
		t.Fatal("confirmed bound not exact")
	}
	// 已接受但未Applied仍经cold复验保留，不能作为历史包被删除。
	cfg.ProtectedState = slot.read()
	cold, e := New(cfg)
	if e != nil {
		t.Fatal("cold original", e)
	}
	defer cold.Close()
	coldRecord := cold.state.DAGManagement.Records[in.ID]
	if coldRecord == nil || coldRecord.Applied || coldRecord.Sequence != control.Sequence || !coldRecord.Attempted || !bytes.Equal(coldRecord.Packet, packet) {
		t.Fatal("cold original state promoted or changed")
	}
	bad := clone(w.state)
	bad.DAGManagement.Records[in.ID].Sequence = tx.ControlCheckpoint().Sequence
	temporary := &Workflow{state: bad, signing: w.signing, receiving: w.receiving, engine: w.engine, now: w.now}
	if _, e = temporary.verifyDAGReceiverHistory(c); !errors.Is(e, ErrDAGProtectedState) {
		t.Fatal("same basis sequence was not precisely rejected", e)
	}
	if posts.Load() != 0 || !bytes.Equal(before, slot.read()) {
		t.Fatal("metadata verification wrote transaction")
	}
}
func environmentValueForDAGManagement(t *testing.T, s string) uint64 {
	t.Helper()
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	return n
}
