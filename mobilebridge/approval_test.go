package mobilebridge

import (
	"bytes"
	"strings"
	"testing"
)

func TestApprovalChoicesStrictBoundedAndNoServerAuthority(t *testing.T) {
	valid := `[{"environmentId":"env","role":"rw","expiresAt":"1234567890"}]`
	choices, e := parseApprovalSelections(valid)
	if e != nil || len(choices) != 1 || choices[0].Role != "rw" {
		t.Fatal("explicit selection rejected")
	}
	for _, raw := range []string{
		`[]`, `null`, valid + ` {}`, `[{"environmentId":"env","role":"rw","expiresAt":"01"}]`,
		`[{"environmentId":"env","role":"owner","expiresAt":"0"}]`,
		`[{"environmentId":"env","role":"rw","role":"admin","expiresAt":"0"}]`,
		`[{"environmentId":"env","role":"rw","expiresAt":"0","issuerProof":{}}]`,
		`[{"environmentId":"env","role":"rw","expiresAt":"0"},{"environmentId":"env","role":"ro","expiresAt":"0"}]`,
		`[{"environmentId":"env","role":"rw"}]`, `[{"environmentId":"env","role":"rw","expiresAt":0}]`,
		`[{"environmentId":"env","role":"rw","expiresAt":"-1"}]`, strings.Repeat(" ", 8193),
	} {
		if _, e := parseApprovalSelections(raw); e == nil {
			t.Fatal("invalid choices accepted")
		}
	}
	// 独立数量门槛，环境须不同。
	tooMany := `[`
	for i := 0; i < 17; i++ {
		if i > 0 {
			tooMany += ","
		}
		tooMany += `{"environmentId":"env` + string(rune('a'+i)) + `","role":"rw","expiresAt":"0"}`
	}
	tooMany += `]`
	if _, e := parseApprovalSelections(tooMany); e == nil {
		t.Fatal("too many choices accepted")
	}
}
func TestApprovalShortCodeNeverJSONAndClosedBytesCleared(t *testing.T) {
	raw := `{"version":1,"operation":"approvePairing","endpoint":"https://vault.example.invalid","pairingId":"pair-native","selections":"[{\"environmentId\":\"env\",\"role\":\"rw\",\"expiresAt\":\"0\"}]"}`
	if _, e := parseWorkflowCommand(raw); e != nil {
		t.Fatal("public intent rejected")
	}
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	w, e := d.OpenWorkflow("https://vault.example.invalid", "synthetic-app/approval/v1", nil, nil, &memorySealed{})
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	if _, e = w.Execute(raw); e == nil {
		t.Fatal("JSON-only approval accepted")
	}
	for _, code := range [][]byte{[]byte("not-code"), []byte("12345678")} {
		w.Close()
		if _, e = w.ExecuteApproval(raw, code); e == nil {
			t.Fatal("closed approval accepted")
		}
		if !bytes.Equal(code, make([]byte, len(code))) {
			t.Fatal("short code survived failed operation")
		}
	}
	if _, e := parseWorkflowCommand(strings.TrimSuffix(raw, "}") + `,"shortCode":"12345678"}`); e == nil {
		t.Fatal("short code in JSON accepted")
	}
}
