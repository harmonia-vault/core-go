package mobilebridge

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
)

func TestNativeDAGProfileSeparateCompiledDomainList(t *testing.T) {
	raw, e := DAGWorkflowProfile()
	if e != nil {
		t.Fatal(e)
	}
	var profile struct {
		Version      int      `json:"version"`
		Profile      string   `json:"profile"`
		Experimental bool     `json:"experimental"`
		Real         bool     `json:"realVaultReady"`
		System       bool     `json:"systemAuthenticationPerOperation"`
		Dispatch     string   `json:"dispatch"`
		Operations   []string `json:"operations"`
	}
	if json.Unmarshal([]byte(raw), &profile) != nil || profile.Version != 1 || profile.Profile != cryptox.RecoveryDAGCapability || !profile.Experimental || profile.Real || !profile.System || profile.Dispatch != "executeDAGRecovery" || !sort.StringsAreSorted(profile.Operations) || len(profile.Operations) != len(dagNativeFields)-1 {
		t.Fatal("compiled profile changed authority or list")
	}
	ordinary, e := WorkflowProfile()
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, op := range profile.Operations {
		if _, ok := dagNativeFields[op]; !ok || seen[op] || op == "cancelDAGRecoveryOwner" || strings.Contains(ordinary, `"`+op+`"`) {
			t.Fatal("unsupported/duplicate/native-only/ordinary operation")
		}
		seen[op] = true
	}
	if !seen["dagRecoveryResolutionDiscovery"] {
		t.Fatal("missing cold discovery route")
	}
}

func TestNativeDAGResolutionDiscoveryStrictProjectionAndZeroCode(t *testing.T) {
	if ValidateDAGRecoveryCommand(dagCommand("dagRecoveryResolutionDiscovery"), 0) != nil || ValidateDAGRecoveryCommand(dagCommand("dagRecoveryResolutionDiscovery"), 1) == nil {
		t.Fatal("discovery code boundary")
	}
	if ValidateDAGRecoveryCommand(recoveredNativeCommand("dagRecoveryResolutionDiscovery", map[string]string{"operationId": "invented"}), 0) == nil {
		t.Fatal("caller target accepted")
	}
	for _, state := range []string{"none", "unsupported", "supported-original", "closed"} {
		x := mobileworkflow.RecoveryDAGResolutionDiscovery{Version: 1, Profile: cryptox.RecoveryOperationClosureCapability, State: state}
		if state == "closed" || state == "supported-original" {
			x.OperationID = "original-id"
			x.TargetHash = strings.Repeat("a", 64)
		}
		out, e := nativeDAGResolutionDiscovery(x)
		if e != nil || len(out) != 6 || out["trustedDevice"] != false {
			t.Fatal("valid discovery projection", e)
		}
		if x.OperationID == "" {
			x.OperationID = "invented"
		} else {
			x.TargetHash = ""
		}
		if _, e = nativeDAGResolutionDiscovery(x); e == nil {
			t.Fatal("ambiguous target projection")
		}
	}
	if _, e := nativeDAGResolutionDiscovery(mobileworkflow.RecoveryDAGResolutionDiscovery{Version: 1, Profile: cryptox.RecoveryOperationClosureCapability, State: "unknown"}); e == nil {
		t.Fatal("unknown state accepted")
	}
}

func TestNativeDAGResolutionDiscoveryFreshZeroNetworkNoCAS(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")
		hits.Add(1)
		w.WriteHeader(500)
	}))
	defer server.Close()
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	slot := &typedAtomicNativeFixture{}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	v, e := d.OpenAtomicWorkflow(server.URL, "synthetic.discovery\x00harmonia/workflow-state/v1\x00slot", nil, ca, slot)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	registry, e := NewNativeDAGRegistry("synthetic.discovery", "slot", 47)
	if e != nil {
		t.Fatal(e)
	}
	defer registry.Close()
	if e = v.AttachDAGRegistry(registry); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(map[string]any{"version": 1, "endpoint": server.URL, "operation": "dagRecoveryResolutionDiscovery"})
	reply, e := v.ExecuteDAGRecovery(string(raw), nil)
	if e != nil {
		t.Fatal(e)
	}
	var out map[string]any
	if json.Unmarshal([]byte(reply), &out) != nil || out["ok"] != true || out["trustedDevice"] != false || out["data"].(map[string]any)["state"] != "none" {
		t.Fatal("fresh native discovery missing")
	}
	if hits.Load() != 0 || slot.cas != 0 || len(slot.read()) != 0 {
		t.Fatal("discovery performed network/save")
	}
	v.Invalidate()
	if reply, e = v.ExecuteDAGRecovery(string(raw), nil); e == nil || reply != "" {
		t.Fatal("invalidated native scope exposed state")
	}
}
