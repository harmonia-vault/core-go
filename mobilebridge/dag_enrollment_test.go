package mobilebridge

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestV5ExplicitProfileAndSecretRoutesRemainClosed(t *testing.T) {
	raw, err := WorkflowProfile()
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Ready       bool     `json:"realVaultReady"`
		Operations  []string `json:"operations"`
		Unsupported []string `json:"unsupported"`
	}
	if json.Unmarshal([]byte(raw), &p) != nil || p.Ready {
		t.Fatal("overall ready changed")
	}
	has := func(xs []string, value string) bool {
		for _, x := range xs {
			if x == value {
				return true
			}
		}
		return false
	}
	for _, op := range []string{"approvePairingV5", "enrollDeviceV5", "rotateEnvironmentKey"} {
		if !has(p.Operations, op) {
			t.Fatal("explicit operation missing")
		}
	}
	for _, op := range []string{"recover", "rotateRecovery"} {
		if !has(p.Unsupported, op) {
			t.Fatal("recovery gate changed")
		}
	}
	d, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	w, err := d.OpenWorkflow("https://vault.example.invalid", "synthetic-v3/native", nil, nil, &memorySealed{})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	enroll := `{"version":1,"operation":"enrollDeviceV5","endpoint":"https://vault.example.invalid","email":"synthetic@example.invalid","password":"synthetic-only","pairingId":"pair","approverDeviceId":"manager"}`
	approve := `{"version":1,"operation":"approvePairingV5","endpoint":"https://vault.example.invalid","pairingId":"pair","selections":"[{\"environmentId\":\"env\",\"role\":\"rw\",\"expiresAt\":\"0\"}]"}`
	for _, command := range []string{enroll, approve} {
		if _, err = w.Execute(command); err == nil {
			t.Fatal("JSON-only secret operation accepted")
		}
	}
	for _, command := range []string{strings.TrimSuffix(enroll, "}") + `,"shortCode":"12345678"}`, strings.TrimSuffix(approve, "}") + `,"issuerProof":{}}`, strings.Replace(enroll, `"pairingId":"pair"`, `"pairingId":"pair","pairingId":"changed"`, 1)} {
		if _, err = parseWorkflowCommand(command); err == nil {
			t.Fatal("untrusted secret/authority/duplicate accepted")
		}
	}
	for _, attempt := range []struct {
		command    string
		enrollment bool
	}{{approve, true}, {enroll, false}} {
		code := []byte("12345678")
		if attempt.enrollment {
			_, err = w.ExecuteEnrollment(attempt.command, code)
		} else {
			_, err = w.ExecuteApproval(attempt.command, code)
		}
		if err == nil || !bytes.Equal(code, make([]byte, 8)) {
			t.Fatal("cross-route accepted or code retained")
		}
	}
	w.Close()
	code := []byte("12345678")
	if _, err = w.ExecuteEnrollment(enroll, code); err == nil || !bytes.Equal(code, make([]byte, 8)) {
		t.Fatal("closed enrollment accepted or code retained")
	}
}
