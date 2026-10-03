package syncclient

import (
	"encoding/json"
	"github.com/harmonia-vault/core-go/cryptox"
	"os"
	"testing"
)

func TestConfirmedRecoveredDAGResultOriginalOnly(t *testing.T) {
	raw, e := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var vector struct {
		Pin   cryptox.PinnedIssuerRoot  `json:"rootPin"`
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("vector")
	}
	var accepted *cryptox.AcceptedRecoveredDeviceV2
	idx := 0
	for i, r := range vector.Proof.Records {
		if r.RecoveredV2 != nil {
			accepted = r.RecoveredV2
			idx = i
			break
		}
	}
	if accepted == nil {
		t.Fatal("recovered vector absent")
	}
	sub := accepted.Submission
	hash, e := cryptox.RecoveredDeviceReferenceHashV2(sub)
	if e != nil {
		t.Fatal(e)
	}
	p := ProtectedDAGOperation{Version: 1, Endpoint: "https://synthetic.invalid", AccountID: vector.Pin.AccountID, AccountGeneration: 1, Pin: vector.Pin, Kind: "recovered-v2", OperationID: sub.Enrollment.OperationID, ContentHash: hash, Recovered: &cryptox.RecoveredDeviceCommandV2{Submission: sub, DependencyBundle: cryptox.RecoveryDependencyBundle{Initialization: vector.Proof.Initialization, Records: vector.Proof.Records[:idx]}}, Attempted: true, AcceptedSequence: accepted.Sequence, Applied: true}
	before, _ := json.Marshal(p)
	got, e := RecoveredDAGResultFromConfirmedOperation(p)
	if e != nil || got.Accepted.Sequence != accepted.Sequence {
		t.Fatal("valid confirmed tuple", e)
	}
	after, _ := json.Marshal(p)
	if string(before) != string(after) {
		t.Fatal("original mutated")
	}
	if _, e = cryptox.VerifyIssuerRecoveryDAG(vector.Pin, got.Evidence); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"unattempted", "unaccepted", "not-applied", "hash", "sequence", "signature", "kind"} {
		bad := cloneDAGOperation(p)
		switch mode {
		case "unattempted":
			bad.Attempted = false
		case "unaccepted":
			bad.AcceptedSequence = 0
			bad.Applied = false
		case "not-applied":
			bad.Applied = false
		case "hash":
			bad.ContentHash = "00"
		case "sequence":
			bad.AcceptedSequence++
		case "signature":
			bad.Recovered.Submission.DeviceSignature = "bad"
		case "kind":
			bad.Kind = "transition-v2"
		}
		if _, e = RecoveredDAGResultFromConfirmedOperation(bad); e == nil {
			t.Fatal("accepted bad", mode)
		}
	}
}
