package mobilebridge

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
)

func TestNativeDAGResolutionStrictTargetAndCodeBoundary(t *testing.T) {
	for _, op := range []string{"queryDAGRecoveryResolution", "closeDAGRecoveryOriginal"} {
		valid := map[string]string{"operationId": "original-id", "targetHash": strings.Repeat("a", 64)}
		if ValidateDAGRecoveryCommand(recoveredNativeCommand(op, valid), 1) != nil || ValidateDAGRecoveryCommand(recoveredNativeCommand(op, valid), 0) == nil {
			t.Fatal("resolution exact fields/code boundary")
		}
		for _, fields := range []map[string]string{
			{"operationId": "original-id"}, {"operationId": "original-id", "targetHash": ""},
			{"operationId": "original-id", "targetHash": strings.Repeat("A", 64)},
			{"operationId": "invalid id", "targetHash": strings.Repeat("a", 64)},
			{"operationId": "original-id", "targetHash": strings.Repeat("a", 64), "mode": "resolve-or-close"},
			{"operationId": "original-id", "targetHash": strings.Repeat("a", 64), "sessionToken": "synthetic"},
		} {
			if ValidateDAGRecoveryCommand(recoveredNativeCommand(op, fields), 1) == nil {
				t.Fatal("caller target/mode/token accepted")
			}
		}
	}
	if ValidateDAGRecoveryCommand(dagCommand("openDAGRecoveryAfterClosure"), 1) != nil || ValidateDAGRecoveryCommand(dagCommand("openDAGRecoveryAfterClosure"), 0) == nil || ValidateDAGRecoveryCommand(dagCommand("dagRecoveryResolutionInfo"), 1) == nil {
		t.Fatal("fresh fullcode requirement changed")
	}
}
func TestNativeDAGResolutionProjectionNeverGrantsTrust(t *testing.T) {
	base := mobileworkflow.RecoveryDAGResolutionResult{Version: 1, Profile: cryptox.RecoveryOperationClosureCapability, OperationID: "original-id", TargetHash: strings.Repeat("a", 64), Observation: "unknown", LocalState: "pending", Confirmation: "none", RotationRequired: true}
	for _, state := range []string{"unknown", "pending", "closed", "accepted"} {
		x := base
		x.Observation = state
		if state == "closed" {
			x.LocalState = "closed"
			x.Confirmation = "native-confirmed"
			x.Sequence = math.MaxUint64
		}
		if state == "accepted" {
			x.LocalState = "accepted-original-confirmed"
			x.Confirmation = "original-history-confirmed"
			x.Sequence = math.MaxUint64
		}
		out, e := nativeDAGResolution(x)
		if e != nil || out["trustedDevice"] != false {
			t.Fatal("mature resolution projection", e)
		}
		if state == "closed" && out["sequence"] != "18446744073709551615" {
			t.Fatal("checkpoint precision lost")
		}
		raw, _ := json.Marshal(out)
		for _, forbidden := range []string{"sessionToken", "privateKey", "recoveryCode", "signature", "envelope", "knownChallengeHash"} {
			if bytes.Contains(raw, []byte(forbidden)) {
				t.Fatal("private source projected")
			}
		}
	}
	for _, modify := range []func(*mobileworkflow.RecoveryDAGResolutionResult){
		func(x *mobileworkflow.RecoveryDAGResolutionResult) { x.TrustedDevice = true },
		func(x *mobileworkflow.RecoveryDAGResolutionResult) { x.Profile = cryptox.RecoveryDAGCapability },
		func(x *mobileworkflow.RecoveryDAGResolutionResult) { x.RotationRequired = false },
		func(x *mobileworkflow.RecoveryDAGResolutionResult) { x.TargetHash = "" },
		func(x *mobileworkflow.RecoveryDAGResolutionResult) { x.OperationID = "" },
		func(x *mobileworkflow.RecoveryDAGResolutionResult) {
			x.LocalState = "closed"
			x.Observation = "closed"
			x.Confirmation = "native-confirmed"
		},
		func(x *mobileworkflow.RecoveryDAGResolutionResult) { x.Observation = "accepted" },
	} {
		x := base
		modify(&x)
		if _, e := nativeDAGResolution(x); e == nil {
			t.Fatal("unconfirmed/foreign resolution projected")
		}
	}
}
func TestNativeDAGResolutionNoOriginalOrRetiredScopeZeroTraffic(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")
		requests.Add(1)
		w.WriteHeader(500)
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	for _, op := range []string{"dagRecoveryResolutionInfo", "queryDAGRecoveryResolution", "closeDAGRecoveryOriginal", "openDAGRecoveryAfterClosure"} {
		d, e := NewDevice()
		if e != nil {
			t.Fatal(e)
		}
		r, e := NewNativeDAGRegistry("synthetic.closure", "slot", 41)
		if e != nil {
			t.Fatal(e)
		}
		slot := &typedAtomicNativeFixture{}
		v, e := d.OpenAtomicWorkflow(server.URL, "synthetic.closure\x00harmonia/workflow-state/v1\x00slot", nil, ca, slot)
		if e != nil {
			t.Fatal(e)
		}
		if e = v.AttachDAGRegistry(r); e != nil {
			t.Fatal(e)
		}
		c := map[string]any{"version": 1, "endpoint": server.URL, "operation": op}
		var code []byte
		if codeRequired(op) {
			complete, e := cryptox.EncodeRecoveryCode(bytes.Repeat([]byte{57}, 32))
			if e != nil {
				t.Fatal(e)
			}
			code = []byte(complete)
		}
		if op == "queryDAGRecoveryResolution" || op == "closeDAGRecoveryOriginal" {
			c["operationId"] = "original-id"
			c["targetHash"] = strings.Repeat("a", 64)
		}
		raw, _ := json.Marshal(c)
		out, e := v.ExecuteDAGRecovery(string(raw), code)
		if e == nil || out != "" || requests.Load() != 0 || len(slot.read()) != 0 || !bytes.Equal(code, make([]byte, len(code))) {
			t.Fatal("no original fabricated closure/auth traffic")
		}
		if !r.dead.Load() {
			t.Fatal("failed scope not retired")
		}
		if out, e = v.ExecuteDAGRecovery(string(raw), bytes.Repeat([]byte{1}, len(code))); e == nil || out != "" || requests.Load() != 0 {
			t.Fatal("retired scope reused")
		}
		v.Close()
		r.Close()
		d.Close()
	}
}
