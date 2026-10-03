package mobilebridge

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestManagementNoAuthorityInputAndUntrustedCallsFailClosed(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	w, e := d.OpenWorkflow("https://vault.example.invalid", "synthetic-management/native", nil, nil, &memorySealed{})
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	raw := `{"version":1,"endpoint":"https://vault.example.invalid","operation":"prepareDeviceGrant","environmentId":"env","subjectDeviceId":"subject","role":"rw","expiresAt":"0","id":"original"}`
	for _, extra := range []string{`,"signingPublicKey":"untrusted"`, `,"receivingPublicKey":"untrusted"`, `,"envelope":"untrusted"`, `,"packet":"untrusted"`, `,"role":"admin"`} {
		if _, e := parseWorkflowCommand(strings.TrimSuffix(raw, "}") + extra + "}"); e == nil {
			t.Fatal("untrusted authority or duplicate accepted")
		}
	}
	for _, command := range []string{raw, strings.Replace(raw, `"expiresAt":"0"`, `"expiresAt":"01"`, 1), strings.Replace(strings.Replace(raw, `"role":"rw"`, `"role":"none"`, 1), `"expiresAt":"0"`, `"expiresAt":"1"`, 1)} {
		out, e := w.Execute(command)
		if e != nil {
			continue
		}
		var result struct {
			OK   bool            `json:"ok"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal([]byte(out), &result) != nil || result.OK || len(result.Data) > 0 {
			t.Fatal("untrusted management claimed access")
		}
	}
}
