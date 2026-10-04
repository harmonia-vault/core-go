package mobilebridge

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/mobileworkflow"
)

func TestNativeDAGAppliedExactCommandAndRestrictedNoSource(t *testing.T) {
	for _, op := range []string{"applyDAGRecoveredDevice", "restoreDAGRecoveredDevice", "pullDAGRecoveredDevice"} {
		fields := map[string]string{}
		if op == "applyDAGRecoveredDevice" {
			fields = map[string]string{"operationId": "original", "contentHash": strings.Repeat("a", 64)}
		}
		raw := recoveredNativeCommand(op, fields)
		if ValidateDAGRecoveryCommand(raw, 0) != nil || ValidateDAGRecoveryCommand(raw, 1) == nil {
			t.Fatal("exact applied command/code boundary")
		}
		d, e := NewDevice()
		if e != nil {
			t.Fatal(e)
		}
		r, _ := NewNativeDAGRegistry("synthetic.native", "slot", 41)
		s := &typedAtomicNativeFixture{}
		v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic.native\x00harmonia/workflow-state/v1\x00slot", nil, nil, s)
		if e != nil {
			t.Fatal(e)
		}
		if e = v.AttachDAGRegistry(r); e != nil {
			t.Fatal(e)
		}
		if out, e := v.ExecuteDAGRecovery(raw, nil); e == nil || out != "" || len(s.read()) != 0 {
			t.Fatal("unconfirmed/no-source stage became trusted")
		}
		v.Close()
		r.Close()
		d.Close()
		fields["root"] = "synthetic-untrusted-root"
		if ValidateDAGRecoveryCommand(recoveredNativeCommand(op, fields), 0) == nil {
			t.Fatal("caller source/binding supplied")
		}
	}
}
func TestNativeDAGAppliedProjectionRequiresExactProtectedBinding(t *testing.T) {
	b := stateBinding{AccountID: "account", AccountGeneration: "1", DeviceID: "device", Checkpoint: math.MaxUint64}
	x := mobileworkflow.DAGRecoveredView{Version: 1, Profile: cryptox.RecoveryDAGCapability, OperationID: "original", ContentHash: strings.Repeat("a", 64), AcceptedSequence: math.MaxUint64, TrustedDevice: true, View: mobileworkflow.View{DeviceID: "device", Checkpoint: math.MaxUint64, Experimental: true, Environments: []mobileworkflow.ViewEnvironment{{ID: "env", Name: "合成环境", Role: localstate.ReadOnly, Variables: map[string]string{"SYNTHETIC": "synthetic-authorized-value"}}}}}
	p, e := nativeDAGAppliedView(x, b)
	if e != nil || p["trustedDevice"] != true || p["acceptedSequence"] != "18446744073709551615" {
		t.Fatal("mature trusted/precision projection lost")
	}
	view := p["view"].(map[string]any)
	rows := view["environments"].([]map[string]any)
	if rows[0]["variables"].(map[string]string)["SYNTHETIC"] != "synthetic-authorized-value" || p["binding"].(map[string]string)["accountId"] != "account" {
		t.Fatal("authorized read data/binding missing")
	}
	x.View.Environments[0].Variables["SYNTHETIC"] = "changed"
	if rows[0]["variables"].(map[string]string)["SYNTHETIC"] != "synthetic-authorized-value" {
		t.Fatal("mutable view alias")
	}
	raw, _ := json.Marshal(p)
	for _, key := range []string{"sessionToken", "privateKey", "recoveryCode", "signature", "envelope"} {
		if strings.Contains(string(raw), key) {
			t.Fatal("private wire projected")
		}
	}
	for _, modify := range []func(*mobileworkflow.DAGRecoveredView, *stateBinding){
		func(x *mobileworkflow.DAGRecoveredView, b *stateBinding) { x.TrustedDevice = false },
		func(x *mobileworkflow.DAGRecoveredView, b *stateBinding) { b.AccountClosed = true },
		func(x *mobileworkflow.DAGRecoveredView, b *stateBinding) { b.DeviceID = "other" },
		func(x *mobileworkflow.DAGRecoveredView, b *stateBinding) { b.AccountGeneration = "01" },
		func(x *mobileworkflow.DAGRecoveredView, b *stateBinding) { b.Checkpoint = 1 },
		func(x *mobileworkflow.DAGRecoveredView, b *stateBinding) { x.View.Experimental = false },
		func(x *mobileworkflow.DAGRecoveredView, b *stateBinding) { x.AcceptedSequence = 0 },
	} {
		a, c := x, b
		modify(&a, &c)
		if _, e = nativeDAGAppliedView(a, c); e == nil {
			t.Fatal("untrusted/stale protected binding accepted")
		}
	}
}
func TestNativeDAGRecoveredInterruptedMetadataHasNoForeignPending(t *testing.T) {
	x := mobileworkflow.DAGRecoveredInfo{Version: 1, Profile: cryptox.RecoveryDAGCapability, State: "interrupted-original", OperationID: "original-preparation", Phase: "intent", Acceptance: "unknown", NeedsOriginalOwner: true}
	p, e := nativeDAGRecoveredInfo(x, mobileworkflow.RecoveryDAGPendingInfo{Version: 1, Profile: cryptox.RecoveryDAGCapability})
	if e != nil || p["contentHash"] != "" || p["acceptedSequence"] != "0" || p["needsOriginalOwner"] != true || p["trustedDevice"] != false {
		t.Fatal("interrupted preparation fabricated sealed/accepted packet")
	}
}
