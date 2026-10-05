package mobilebridge

import (
	"strings"
	"testing"
)

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
