package mobilebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"github.com/harmonia-vault/core-go/syncclient"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func dagCommand(op string) string {
	return `{"version":1,"endpoint":"https://synthetic.example.invalid","operation":"` + op + `"}`
}
func TestNativeDAGCommandStrictFieldsAndCodeBoundary(t *testing.T) {
	for op := range dagNativeFields {
		raw := dagCommand(op)
		if op == "openDAGRecoveryOwner" {
			raw = raw[:len(raw)-1] + `,"email":"actor@example.invalid","password":"synthetic-only"}`
		}
		if op == "sealDAGRecoveredDevice" {
			raw = recoveredNativeCommand(op, map[string]string{"expectedSequence": "2", "recoveryHeadHash": strings.Repeat("a", 64), "selections": `[{"environmentId":"env","keyVersion":"1","role":"ro","expiresAt":"0"}]`})
		}
		if op == "retryDAGRecoveredDevice" || op == "applyDAGRecoveredDevice" {
			raw = recoveredNativeCommand(op, map[string]string{"operationId": "original-id", "contentHash": strings.Repeat("b", 64)})
		}
		if op == "queryDAGRecoveryResolution" || op == "closeDAGRecoveryOriginal" {
			raw = recoveredNativeCommand(op, map[string]string{"operationId": "original-id", "targetHash": strings.Repeat("c", 64)})
		}
		size := int64(0)
		if codeRequired(op) {
			size = 1
		}
		if ValidateDAGRecoveryCommand(raw, size) != nil {
			t.Fatal("valid fixed native DTO rejected")
		}
		wrong := int64(1)
		if size == 1 {
			wrong = 0
		}
		if ValidateDAGRecoveryCommand(raw, wrong) == nil {
			t.Fatal("code boundary accepted")
		}
	}
	for _, raw := range []string{`{"version":1,"version":1,"endpoint":"https://synthetic.example.invalid","operation":"dagRecoveryPendingInfo"}`, dagCommand("dagRecoveryPendingInfo") + `{}`, `{"version":1,"endpoint":null,"operation":"dagRecoveryPendingInfo"}`, `{"version":1,"endpoint":"http://localhost","operation":"dagRecoveryPendingInfo"}`, `{"version":1,"endpoint":"https://synthetic.example.invalid","operation":"dagRecoveryPendingInfo","trustedDevice":"true"}`, dagCommand("rawSign"), `{"version":1,"endpoint":"https://synthetic.example.invalid","operation":"openDAGRecoveryOwner","email":null,"password":"synthetic"}`, `{"version":1,"endpoint":"https://synthetic.example.invalid","operation":"openDAGRecoveryOwner","email":"e"}`} {
		if ValidateDAGRecoveryCommand(raw, 0) == nil {
			t.Fatal("invalid native DTO accepted")
		}
	}
	if ValidateDAGRecoveryCommand(dagCommand("sealDAGRecoveryTransition"), 513) == nil {
		t.Fatal("unbounded code accepted")
	}
}
func TestNativeDAGProjectionNoTrustedAndExactUint64(t *testing.T) {
	p, e := nativeDAGPending(mobileworkflow.RecoveryDAGPendingInfo{Version: 1, Profile: cryptox.RecoveryDAGCapability, State: "sealed", AcceptedSequence: math.MaxUint64})
	if e != nil {
		t.Fatal(e)
	}
	if p["acceptedSequence"] != "18446744073709551615" || p["trustedDevice"] != false {
		t.Fatal("numeric or trust projection changed")
	}
	if _, e = nativeDAGInfo(syncclient.DAGRecoveryInfo{TrustedDevice: true}); e == nil {
		t.Fatal("DAG trusted projected")
	}
	if _, e = nativeDAGPreparation(mobileworkflow.RecoveryDAGPreparationInfo{Version: 1, Profile: "wrong"}); e == nil {
		t.Fatal("profile replaced")
	}
	b, _ := json.Marshal(p)
	for _, forbidden := range []string{"privateKey", "sessionToken", "ciphertext", "recoveryCode"} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatal("secret in metadata projection")
		}
	}
}
func TestNativeDAGDispatchRequiresExactScopeAndCapturedAtomicStore(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic.native\x00harmonia/workflow-state/v1\x00slot", nil, nil, &typedAtomicNativeFixture{})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	code := []byte("synthetic-complete-code")
	if _, e = v.ExecuteDAGRecovery(dagCommand("sealDAGRecoveryTransition"), code); e == nil {
		t.Fatal("no registry accepted")
	}
	if !bytes.Equal(code, make([]byte, len(code))) {
		t.Fatal("caller code not cleared")
	}
	r, e := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = v.AttachDAGRegistry(r); e != nil {
		t.Fatal(e)
	}
	if _, e = v.ExecuteDAGRecovery(`{"version":1,"endpoint":"https://different.example.invalid","operation":"dagRecoveryPendingInfo"}`, nil); e == nil {
		t.Fatal("endpoint changed")
	}
	if _, e = v.ExecuteDAGRecovery(dagCommand("cancelDAGRecoveryOwner"), nil); e == nil {
		t.Fatal("domain local cancellation accepted")
	}
}
func TestNativeDAGDispatchChecksSnapshotAndDrainsBeforeWorkflowClose(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	r, _ := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	defer r.Close()
	s := &typedAtomicNativeFixture{}
	v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic.native\x00harmonia/workflow-state/v1\x00slot", nil, nil, s)
	if e != nil {
		t.Fatal(e)
	}
	if e = v.AttachDAGRegistry(r); e != nil {
		t.Fatal(e)
	}
	s.packet = []byte{1}
	if _, e = v.ExecuteDAGRecovery(dagCommand("dagRecoveryPendingInfo"), nil); e == nil {
		t.Fatal("changed native snapshot accepted")
	}
	r.mu.Lock()
	active := len(r.active)
	r.mu.Unlock()
	if active != 0 || !r.dead.Load() {
		t.Fatal("failed dispatch not cancelled and drained")
	}
	done := make(chan struct{})
	go func() { v.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close waited un-finished native reservation")
	}
}
func TestNativeDAGMetadataDispatchHasNoOwnerOrTrustUpgrade(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	r, _ := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	defer r.Close()
	for _, op := range []string{"dagRecoveryPreparationInfo", "dagRecoveryPendingInfo"} {
		v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic.native\x00harmonia/workflow-state/v1\x00slot", nil, nil, &typedAtomicNativeFixture{})
		if e != nil {
			t.Fatal(e)
		}
		if e = v.AttachDAGRegistry(r); e != nil {
			t.Fatal(e)
		}
		raw, e := v.ExecuteDAGRecovery(dagCommand(op), nil)
		if e != nil {
			t.Fatal(e)
		}
		var result map[string]any
		if json.Unmarshal([]byte(raw), &result) != nil || result["trustedDevice"] != false || result["ok"] != true {
			t.Fatal("metadata scope changed")
		}
		v.Close()
	}
	if r.dead.Load() || r.opened.Load() {
		t.Fatal("metadata fabricated owner")
	}
}
func TestNativeDAGCancelOnlyRecordedReservation(t *testing.T) {
	r, _ := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	defer r.Close()
	id, ctx, e := r.reserve(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	r.cancelRecorded(id + 1)
	if ctx.Err() != nil {
		t.Fatal("old identity cancelled current operation")
	}
	r.cancelRecorded(id)
	if ctx.Err() == nil {
		t.Fatal("current cancellation missing")
	}
	r.finish(id)
}

func TestNativeDAGLoginScopeCASUpdatesBothHashesAndColdWorkflow(t *testing.T) {
	var logins, dagHits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/login" {
			dagHits.Add(1)
			w.WriteHeader(400)
			return
		}
		logins.Add(1)
		json.NewEncoder(w).Encode(syncclient.LoginResult{AccountID: "synthetic-account", AccountGeneration: "1", Token: cryptox.EncodeBase64(bytes.Repeat([]byte{71}, 32)), ExpiresAt: time.Now().Add(time.Hour).Unix()})
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	s := &typedAtomicNativeFixture{}
	scope := "synthetic.native\x00harmonia/workflow-state/v1\x00slot"
	v, e := d.OpenAtomicWorkflow(server.URL, scope, nil, ca, s)
	if e != nil {
		t.Fatal(e)
	}
	info, e := v.workflow.LoginDAGAccountScope(context.Background(), "actor@example.invalid", "synthetic-password")
	if e != nil || info.TrustedDevice {
		t.Fatal("scope failed")
	}
	if s.cas != 1 || v.binding.AccountID != info.AccountID || v.checkProtected(v.protectedSHA256) != nil {
		t.Fatal("wrapper CAS binding/SHA stale")
	}
	plain, e := v.workflow.ExportProtectedState()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(plain)
	hash := sha256.Sum256(plain)
	if hex.EncodeToString(hash[:]) != v.protectedSHA256 {
		t.Fatal("Go and wrapper whole-state SHA disagree")
	}
	if bytes.Contains(plain, []byte("synthetic-password")) || bytes.Contains(plain, []byte(cryptox.EncodeBase64(bytes.Repeat([]byte{71}, 32)))) {
		t.Fatal("login secret persisted")
	}
	captured := s.read()
	defer clear(captured)
	v.Close()
	cold, e := d.OpenAtomicWorkflow(server.URL, scope, captured, ca, s)
	if e != nil {
		t.Fatal(e)
	}
	defer cold.Close()
	if cold.binding.AccountID != info.AccountID || cold.checkProtected(cold.protectedSHA256) != nil {
		t.Fatal("cold scope lost CAS base")
	}
	reopened, e := cold.workflow.LoginDAGAccountScope(context.Background(), "actor@example.invalid", "synthetic-password")
	if e != nil || reopened.TrustedDevice || s.cas != 2 || logins.Load() != 2 || dagHits.Load() != 0 {
		t.Fatal("same scope reopen failed")
	}
	if cold.checkProtected(cold.protectedSHA256) != nil {
		t.Fatal("reopened SHA stale")
	}
}
func TestNativeDAGLoginCASFailureHasZeroRecoveryTrafficAndRetiresRegistry(t *testing.T) {
	var logins, dagHits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/login" {
			dagHits.Add(1)
			w.WriteHeader(500)
			return
		}
		logins.Add(1)
		json.NewEncoder(w).Encode(syncclient.LoginResult{AccountID: "synthetic-account", AccountGeneration: "1", Token: cryptox.EncodeBase64(bytes.Repeat([]byte{71}, 32)), ExpiresAt: time.Now().Add(time.Hour).Unix()})
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	s := &rejectingNativeDAGCAS{}
	v, e := d.OpenAtomicWorkflow(server.URL, "synthetic.native\x00harmonia/workflow-state/v1\x00slot", nil, ca, s)
	if e != nil {
		t.Fatal(e)
	}
	r, _ := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	defer r.Close()
	if e = v.AttachDAGRegistry(r); e != nil {
		t.Fatal(e)
	}
	raw := `{"version":1,"endpoint":"` + server.URL + `","operation":"openDAGRecoveryOwner","email":"actor@example.invalid","password":"synthetic-password"}`
	if _, e = v.ExecuteDAGRecovery(raw, []byte("synthetic-invalid-code")); e == nil {
		t.Fatal("failed seal returned success")
	}
	v.Close()
	if !r.dead.Load() || s.cas != 1 || logins.Load() != 1 || dagHits.Load() != 0 || len(s.read()) != 0 {
		t.Fatal("failed CAS advanced recovery traffic")
	}
}

type rejectingNativeDAGCAS struct{ typedAtomicNativeFixture }

func (s *rejectingNativeDAGCAS) CompareAndSwapSealed(expected, next []byte) error {
	s.cas++
	return errors.New("synthetic CAS save rejected")
}

func TestNativeDAGAttachCancelLockOrder(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic.native\x00harmonia/workflow-state/v1\x00slot", nil, nil, &typedAtomicNativeFixture{})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	r, _ := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	defer r.Close()
	// 真实Attach被取消gate拦住时，不能持r.mu阻塞cancelRecorded/Invalidate。
	v.cancelMu.Lock()
	done := make(chan error, 1)
	go func() { done <- v.AttachDAGRegistry(r) }()
	deadline := time.Now().Add(time.Second)
	entered := false
	for time.Now().Before(deadline) {
		if !v.mu.TryLock() {
			entered = true
			break
		}
		v.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	registryAvailable := false
	if entered {
		registryAvailable = r.mu.TryLock()
		if registryAvailable {
			r.mu.Unlock()
		}
	}
	v.cancelMu.Unlock()
	select {
	case e = <-done:
	case <-time.After(time.Second):
		t.Fatal("Attach failed to drain cancellation gate")
	}
	if !entered || !registryAvailable || e != nil {
		t.Fatal("Attach held registry gate while waiting cancellation gate")
	}
}

func TestNativeDAGAbsentFromPublicWorkflowSurface(t *testing.T) {
	raw, e := WorkflowProfile()
	if e != nil {
		t.Fatal(e)
	}
	for operation := range dagNativeFields {
		if bytes.Contains([]byte(raw), []byte(operation)) {
			t.Fatal("DAG capability published")
		}
		if _, e = parseWorkflowCommand(dagCommand(operation)); e == nil {
			t.Fatal("DAG ordinary command accepted")
		}
	}
	for _, operation := range []string{"sealDAGRecoveredDevice", "retryDAGRecoveredDevice", "registerRecoveredDAGDevice", "rawSign"} {
		if ValidateDAGRecoveryCommand(dagCommand(operation), 0) == nil {
			t.Fatal("out-of-scope operation accepted")
		}
	}
}

func TestNativeDAGSoftResultRejectsAuthorizationAndBindingErrors(t *testing.T) {
	forbidden := []error{&syncclient.RequestError{Status: 401}, &syncclient.RequestError{Status: 403}, mobileworkflow.ErrDAGOwnerBinding, errors.Join(syncclient.ErrDAGNewCodeMismatch, &syncclient.RequestError{Status: 403}), errors.Join(syncclient.ErrEnrollmentPending, syncclient.ErrTrustInvalidated)}
	for _, err := range forbidden {
		if nativeDAGSoftCandidate("sealDAGRecoveryTransition", err) || nativeDAGSoftCandidate("retryDAGRecoveryTransition", err) || nativeDAGSoftCandidate("openDAGRecoveryOwner", err) {
			t.Fatal("authorization/binding became retained-owner soft result")
		}
	}
	if !nativeDAGSoftCandidate("sealDAGRecoveryTransition", syncclient.ErrDAGNewCodeMismatch) || !nativeDAGSoftCandidate("beginDAGRecoveryTransition", mobileworkflow.ErrDAGCodeAlreadyPrepared) || !nativeDAGSoftCandidate("retryDAGRecoveryTransition", errors.Join(syncclient.ErrEnrollmentPending, &syncclient.RequestError{Status: 504})) {
		t.Fatal("original retry classification lost")
	}
	if nativeDAGSoftCandidate("openDAGRecoveryOwner", errors.Join(syncclient.ErrEnrollmentPending, &syncclient.RequestError{Status: 504})) {
		t.Fatal("other operation generalized to retry")
	}
}
