package syncclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDAGGETStatusRequiresExactExplicitAcceptance(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		kind := "transitionHash"
		if recovered {
			kind = "recoveryEnrollmentHash"
		}
		valid := `{"operationId":"synthetic-original","accepted":true,"sequence":2,"contentHash":"` + strings.Repeat("a", 64) + `","` + kind + `":"` + strings.Repeat("a", 64) + `"}`
		for _, raw := range []string{`{"operationId":"synthetic-original","accepted":false}`, valid} {
			wire := dagStatusReceipt{recovered: recovered}
			if err := strictJSONBytes([]byte(raw), &wire); err != nil {
				t.Fatal("valid exact status rejected", err)
			}
		}
	}
	for name, raw := range map[string]string{
		"missing":          `{"operationId":"synthetic-original"}`,
		"null":             `{"operationId":"synthetic-original","accepted":null}`,
		"string":           `{"operationId":"synthetic-original","accepted":"false"}`,
		"number":           `{"operationId":"synthetic-original","accepted":0}`,
		"duplicate":        `{"operationId":"synthetic-original","accepted":false,"accepted":true}`,
		"extra":            `{"operationId":"synthetic-original","accepted":false,"unexpected":false}`,
		"falseWithZero":    `{"operationId":"synthetic-original","accepted":false,"sequence":0}`,
		"trueMissing":      `{"operationId":"synthetic-original","accepted":true}`,
		"nullID":           `{"operationId":null,"accepted":false}`,
		"missingID":        `{"accepted":false}`,
		"trailing":         `{"operationId":"synthetic-original","accepted":false} {}`,
		"wrongKind":        `{"operationId":"synthetic-original","accepted":true,"sequence":2,"contentHash":"a","recoveryEnrollmentHash":"a"}`,
		"nullSequence":     `{"operationId":"synthetic-original","accepted":true,"sequence":null,"contentHash":"a","transitionHash":"a"}`,
		"fractionSequence": `{"operationId":"synthetic-original","accepted":true,"sequence":2.5,"contentHash":"a","transitionHash":"a"}`,
		"nullHash":         `{"operationId":"synthetic-original","accepted":true,"sequence":2,"contentHash":null,"transitionHash":"a"}`,
		"oversize":         `{"operationId":"synthetic-original","accepted":false,"x":"` + strings.Repeat("a", 4096) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			wire := dagStatusReceipt{}
			if err := strictJSONBytes([]byte(raw), &wire); err == nil {
				t.Fatal("malformed status became an acceptance observation")
			}
		})
	}
}

func TestDAGGETQueryRejectsOriginalMismatch(t *testing.T) {
	p := checkedOriginal(t)
	var body atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/"+p.OperationID) {
			t.Error("query changed method or original ID")
		}
		w.Header().Set("Harmonia-Protocol-Major", "2")
		_, _ = w.Write(body.Load().([]byte))
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	s := &DAGRecoverySession{config: DAGRecoveryConfig{Endpoint: server.URL, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration}, endpoint: u, http: server.Client()}
	var base uint64
	_ = json.Unmarshal([]byte(p.Transition.Submission.Transition.ExpectedSequence), &base)
	accepted := DAGReceipt{OperationID: p.OperationID, Accepted: true, Sequence: base + 1, ContentHash: p.ContentHash, TransitionHash: p.ContentHash}
	for name, change := range map[string]func(*DAGReceipt){
		"id":       func(r *DAGReceipt) { r.OperationID = "other-original" },
		"hash":     func(r *DAGReceipt) { r.ContentHash = strings.Repeat("0", 64) },
		"sequence": func(r *DAGReceipt) { r.Sequence++ },
		"kind":     func(r *DAGReceipt) { r.RecoveryEnrollmentHash = r.TransitionHash; r.TransitionHash = "" },
	} {
		t.Run(name, func(t *testing.T) {
			receipt := accepted
			change(&receipt)
			raw, _ := json.Marshal(receipt)
			body.Store(raw)
			if _, err := s.query(context.Background(), p); err == nil {
				t.Fatal("mismatched original receipt accepted")
			}
		})
	}
	body.Store([]byte(`{"operationId":"` + p.OperationID + `","accepted":false}`))
	p.AcceptedSequence = base + 1
	if _, err := s.query(context.Background(), p); err == nil {
		t.Fatal("known accepted fact regressed to false")
	}
	raw, _ := json.Marshal(accepted)
	body.Store(raw)
	if out, err := s.query(context.Background(), p); err != nil || !out.Accepted {
		t.Fatal("valid exact original receipt rejected", err)
	}
}

func TestDAGPOSTReceiptDoesNotUseGETShape(t *testing.T) {
	p := checkedOriginal(t)
	base := p.Transition.Submission.Transition.ExpectedSequence
	var n uint64
	if json.Unmarshal([]byte(base), &n) != nil {
		t.Fatal("synthetic sequence")
	}
	raw, _ := json.Marshal(map[string]any{"sequence": n + 1, "contentHash": p.ContentHash, "transitionHash": p.ContentHash, "replayed": false})
	var out DAGReceipt
	if strictJSONBytes(raw, &out) != nil || expectedDAGReceipt(out, p.OperationID, p.ContentHash, base, false, false) != nil {
		t.Fatal("POST receipt incorrectly required status-only fields")
	}
}
