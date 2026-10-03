package syncclient

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"net/http"
	"os"
	"testing"
)

func TestRecoveryOperationClosedHistoryChecksFullVerifiedCandidates(t *testing.T) {
	raw, e := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Pin   cryptox.PinnedIssuerRoot  `json:"rootPin"`
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public fixture")
	}
	proof, e := cryptox.VerifyIssuerRecoveryDAG(f.Pin, f.Proof)
	if e != nil {
		t.Fatal(e)
	}
	prefix := cryptox.RecoveryDependencyBundle{Initialization: f.Proof.Initialization, Records: f.Proof.Records[:2]}
	prior, e := cryptox.VerifyRecoveryDependencyBundle(f.Pin, prefix)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = cryptox.VerifyRecoveryDAGAdvance(prior, f.Proof); e != nil {
		t.Fatal("legitimate complete advance prerequisite", e)
	}
	full := cryptox.RecoveryDependencyBundle{Initialization: f.Proof.Initialization, Records: f.Proof.Records}
	if _, e = cryptox.VerifyRecoveryDependencyBundle(f.Pin, full); e != nil {
		t.Fatal("legitimate complete bundle prerequisite", e)
	}
	id := f.Proof.Records[2].TransitionV2.Submission.Transition.OperationID
	for _, mode := range []string{"same-id", "same-sequence", "non-conflicting"} {
		t.Run(mode, func(t *testing.T) {
			closed := DAGClosedOperationCheckpoint{OperationID: id, Sequence: 70}
			v := DAGVault{Sequence: 70, DependencyBundle: full, IssuerEvidence: f.Proof}
			switch mode {
			case "same-sequence":
				closed.OperationID = "synthetic-distinct-closed-id"
				closed.Sequence = 40
			case "non-conflicting":
				closed.OperationID = "synthetic-unaccepted-closed-id"
			}
			c := DAGRecoveryConfig{Pin: &f.Pin, PriorBundle: &prefix, MinimumSequence: closed.Sequence, ClosedOperations: []DAGClosedOperationCheckpoint{closed}}
			err := validateDAGHistoryCheckpoint(c, v, proof)
			if mode == "non-conflicting" {
				if err != nil {
					t.Fatal("legal complete extension rejected", err)
				}
			} else if !errors.Is(err, ErrDAGClosedHistoryConflict) {
				t.Fatal("valid incoming accepted history escaped closed constraint", err)
			}
		})
	}
	if e = ValidateDAGClosedHistory([]DAGClosedOperationCheckpoint{{OperationID: id, Sequence: 70}}, prefix.Records); e != nil {
		t.Fatal("accepted prefix before closed remains legitimate", e)
	}
	for _, records := range [][]cryptox.RecoveryDAGRecord{full.Records, f.Proof.Records} {
		if e = ValidateDAGClosedHistory([]DAGClosedOperationCheckpoint{{OperationID: id, Sequence: 70}}, records); !errors.Is(e, ErrDAGClosedHistoryConflict) {
			t.Fatal("legitimate bundle/proof records escaped shared closed check", e)
		}
	}

}

func TestRecoveryOperationClosedConfigurationImmutableAndPreflight(t *testing.T) {
	p := checkedOriginal(t)
	source := []DAGClosedOperationCheckpoint{{OperationID: "synthetic-closed", Sequence: 80}}
	c := DAGRecoveryConfig{Endpoint: p.Endpoint, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, Pin: &p.Pin, PriorBundle: &p.Transition.DependencyBundle, MinimumSequence: 80, ClosedOperations: source, Journal: &b1BindingJournal{}}
	frozen, e := freezeDAGClosedHistoryConfig(c)
	if e != nil {
		t.Fatal(e)
	}
	source[0].OperationID = "synthetic-replaced"
	if frozen.ClosedOperations[0].OperationID != "synthetic-closed" {
		t.Fatal("caller could delete owner closed guard")
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			source[0] = DAGClosedOperationCheckpoint{OperationID: "synthetic-concurrent-change", Sequence: 81}
		}
		close(done)
	}()
	for i := 0; i < 100; i++ {
		if frozen.ClosedOperations[0].OperationID != "synthetic-closed" || frozen.ClosedOperations[0].Sequence != 80 {
			t.Fatal("caller concurrently modified owner bounds")
		}
	}
	<-done
	for _, mode := range []string{"missing-prior", "future-closed", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			config := frozen
			switch mode {
			case "missing-prior":
				config.PriorBundle = nil
			case "future-closed":
				config.MinimumSequence = 79
			case "duplicate":
				config.ClosedOperations = append(config.ClosedOperations, config.ClosedOperations[0])
			}
			tr := &resolutionForbiddenTransport{}
			config.HTTPClient = &http.Client{Transport: tr}
			if _, e := OpenDAGRecoverySession(context.Background(), config, "synthetic invalid code"); e == nil || tr.posts != 0 {
				t.Fatal("malformed closed constraint reached network", e, tr.posts)
			}
		})
	}
}
