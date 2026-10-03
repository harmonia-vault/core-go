package mobilebridge

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecoveryRegistryNativeOnlyAndMissingOwnerKeepsValuesClosed(t *testing.T) {
	const app = "org.harmoniavault.synthetic"
	const slot = "synthetic-recovery.gcm"
	r, e := NewRecoveryRegistry(app, slot)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if _, e = json.Marshal(r); e == nil {
		t.Fatal("registry serialized")
	}
	for _, s := range []string{"", "../other", "invalid\x00slot"} {
		if _, e = NewRecoveryRegistry(app, s); e == nil {
			t.Fatal("unsafe slot accepted")
		}
	}
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	w, e := d.OpenWorkflow("https://vault.example.invalid", app+"\x00harmonia/workflow-state/v1\x00"+slot, nil, nil, &memorySealed{})
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	if e = w.AttachRecoveryRegistry(r); e != nil {
		t.Fatal(e)
	}
	out, e := w.Execute(`{"version":1,"endpoint":"https://vault.example.invalid","operation":"recoveryView"}`)
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		OK   bool            `json:"ok"`
		Code string          `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal([]byte(out), &v) != nil || v.OK || v.Code != "RECOVERY_RESTART_REQUIRED" || len(v.Data) > 0 {
		t.Fatal("missing RAM owner returned cache")
	}
	wrong, e := NewRecoveryRegistry(app, "different.gcm")
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	if w.AttachRecoveryRegistry(wrong) == nil {
		t.Fatal("cross-slot registry accepted")
	}
	w.Cancel()
	r.Close()
	if w.AttachRecoveryRegistry(r) == nil {
		t.Fatal("disposed registry revived")
	}
}
func TestRecoveryAuthorityInputsCannotSupplyOwnerOrSignature(t *testing.T) {
	raw := `{"version":1,"endpoint":"https://vault.example.invalid","operation":"completeRecoveryTransition","recoveryCode":"synthetic-invalid"}`
	for _, field := range []string{"owner", "handle", "privateKey", "sessionToken", "authority", "signature", "recoveryCode"} {
		if _, e := parseWorkflowCommand(strings.TrimSuffix(raw, "}") + `,"` + field + `":"untrusted"}`); e == nil {
			t.Fatal("untrusted authority or duplicate accepted")
		}
	}
	for _, old := range []string{"recover", "rotateRecovery", "rawSign"} {
		if _, e := parseWorkflowCommand(strings.Replace(raw, "completeRecoveryTransition", old, 1)); e == nil {
			t.Fatal("legacy/arbitrary sign opened")
		}
	}
}
