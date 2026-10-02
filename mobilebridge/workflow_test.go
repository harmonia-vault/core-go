package mobilebridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

type memorySealed struct {
	packet []byte
	fail   bool
}

func (s *memorySealed) SaveSealed(p []byte) error {
	if s.fail {
		return errors.New("synthetic save failure")
	}
	s.packet = bytes.Clone(p)
	return nil
}
func TestWorkflowProtectedStateBindingAndClose(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	store := &memorySealed{}
	w, e := d.OpenWorkflow("https://vault.example.invalid", "synthetic-app/slot/v1", nil, nil, store)
	if e != nil {
		t.Fatal(e)
	}
	plain, e := w.workflow.ExportProtectedState()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(plain)
	if e = w.save(plain); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(store.packet, []byte("signingPublicKey")) == false {
		t.Fatal("AAD binding absent")
	}
	if bytes.Contains(store.packet, []byte(`"grants"`)) {
		t.Fatal("protected context leaked")
	}
	restored, e := d.OpenWorkflow("https://vault.example.invalid", "synthetic-app/slot/v1", store.packet, nil, store)
	if e != nil {
		t.Fatal(e)
	}
	restored.Close()
	for _, input := range []struct {
		endpoint, slot string
		packet         []byte
	}{
		{"https://other.example.invalid", "synthetic-app/slot/v1", store.packet},
		{"https://vault.example.invalid", "other-app/slot/v1", store.packet},
	} {
		if other, e := d.OpenWorkflow(input.endpoint, input.slot, input.packet, nil, store); e == nil {
			other.Close()
			t.Fatal("cross-binding accepted")
		}
	}
	other, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if flow, e := other.OpenWorkflow("https://vault.example.invalid", "synthetic-app/slot/v1", store.packet, nil, store); e == nil {
		flow.Close()
		t.Fatal("cross-device accepted")
	}
	tampered := bytes.Clone(store.packet)
	tampered[len(tampered)-1] ^= 1
	if flow, e := d.OpenWorkflow("https://vault.example.invalid", "synthetic-app/slot/v1", tampered, nil, store); e == nil {
		flow.Close()
		t.Fatal("tamper accepted")
	}
	before := bytes.Clone(store.packet)
	store.fail = true
	if w.save(plain) == nil || !bytes.Equal(before, store.packet) {
		t.Fatal("failed save changed protected packet")
	}
	w.Close()
	if len(w.key) != 0 {
		t.Fatal("state key survived close")
	}
	if _, e = w.Execute(`{"version":1,"operation":"view","endpoint":"https://vault.example.invalid"}`); e == nil {
		t.Fatal("closed flow executed")
	}
}
func TestWorkflowStrictOperationsAndProfile(t *testing.T) {
	valid := `{"version":1,"operation":"setVariable","endpoint":"https://vault.example.invalid","environmentId":"env","name":"SYNTHETIC","value":"only-synthetic","id":"stable-id"}`
	if _, e := parseWorkflowCommand(valid); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{
		`{"version":1,"operation":"view","endpoint":"https://vault.example.invalid","token":"server-session"}`,
		`{"version":1,"operation":"view","endpoint":"https://vault.example.invalid","operation":"pull"}`,
		`{"version":1,"operation":"approveDevice","endpoint":"https://vault.example.invalid"}`,
		`{"version":1,"operation":"view","endpoint":"http://vault.example.invalid"}`,
		`{"version":1,"operation":"view","endpoint":"https://vault.example.invalid","protectedState":"injected"}`,
	} {
		if _, e := parseWorkflowCommand(raw); e == nil {
			t.Fatal("invalid workflow input accepted")
		}
	}
	raw, e := WorkflowProfile()
	if e != nil {
		t.Fatal(e)
	}
	var p map[string]any
	if json.Unmarshal([]byte(raw), &p) != nil || p["realVaultReady"] != false {
		t.Fatal("global ready enabled")
	}
	if _, e := workflowHTTPClient([]byte("not-a-certificate")); e == nil {
		t.Fatal("invalid explicit CA accepted")
	}
}
