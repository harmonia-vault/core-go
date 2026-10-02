package mobileworkflow

import (
	"encoding/json"
	"github.com/harmonia-vault/core-go/cryptox"
	"testing"
)

func TestApprovalExplicitSelectionBoundsAndCanonicalChoiceHash(t *testing.T) {
	valid := []ApprovalSelection{{"env-B", "rw", "0"}, {"env-A", "ro", "2030001000"}}
	a, e := choicesHash("pair-1", valid)
	if e != nil {
		t.Fatal(e)
	}
	b, e := choicesHash("pair-1", []ApprovalSelection{valid[1], valid[0]})
	if e != nil || a != b {
		t.Fatal("choice order changed hash")
	}
	for _, bad := range [][]ApprovalSelection{nil, {{"env", "none", "0"}}, {{"env", "admin", "01"}}, {{"env", "rw", "-1"}}, {{"env", "ro", "253402300800"}}, {{"env", "ro", "0"}, {"env", "rw", "0"}}, make([]ApprovalSelection, 17)} {
		if _, e = choicesHash("pair-1", bad); e == nil {
			t.Fatal("invalid explicit choices")
		}
	}
	raw, e := json.Marshal(ApprovalInput{PairingID: "pair-1", ShortCode: []byte("12345678"), Selections: valid})
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	if _, ok := fields["ShortCode"]; ok {
		t.Fatal("short code serializable")
	}
}
func TestApprovalInitialAuthorityCannotComeFromCurrentDirectory(t *testing.T) {
	f := newSelfFixture(t)
	w, e := New(f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	w.state.InitialAuthorities = nil // Explicitly remove native synthetic genesis; current grant cannot refill it.
	if _, e = w.initialAuthority("env"); e == nil {
		t.Fatal("current self grant guessed initial evidence")
	}
	w.state.InitialAuthorities = []cryptox.SignedGrantWire{cryptox.GrantToWire(f.grant)}
	if e = w.validateInitialAuthorities(); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"generation", "version", "role", "signing-key", "signature"} {
		t.Run(field, func(t *testing.T) {
			original := w.state.InitialAuthorities[0]
			s := original
			switch field {
			case "generation":
				s.Grant.GrantGeneration = "2"
			case "version":
				s.Grant.KeyVersion = "2"
			case "role":
				s.Grant.Role = "ro"
			case "signing-key":
				s.Grant.SubjectSigningPublicKey = cryptox.EncodeBase64(make([]byte, 32))
			case "signature":
				s.Signature = cryptox.EncodeBase64(make([]byte, 64))
			}
			w.state.InitialAuthorities[0] = s
			if e = w.validateInitialAuthorities(); e == nil {
				t.Fatal("unproven initial source")
			}
			w.state.InitialAuthorities[0] = original
		})
	}
}
