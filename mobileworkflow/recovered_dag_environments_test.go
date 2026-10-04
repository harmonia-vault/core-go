package mobileworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestDAGEnvironmentRestrictedOriginalZeroNetwork(t *testing.T) {
	_, w, _ := b3bConfirmedFixture(t)
	defer w.Close()
	var requests atomic.Int32
	w.http = &http.Client{Transport: b3bRejectTransport{calls: &requests}}
	for _, op := range []string{"create", "rename", "rotate", "delete", "retry"} {
		name := ""
		if op == "create" || op == "rename" {
			name = "synthetic-name"
		}
		if _, e := w.runDAGEnvironment(context.Background(), op, "synthetic-env", "synthetic-env", name, "synthetic-id"); !errors.Is(e, ErrNotTrusted) {
			t.Fatal("restricted source used", op, e)
		}
	}
	if _, e := w.PendingDAGEnvironments(); !errors.Is(e, ErrNotTrusted) {
		t.Fatal(e)
	}
	if requests.Load() != 0 {
		t.Fatal("restricted environment operation used network")
	}
	w.state.DAGEnvironments = &dagEnvironmentJournal{Version: 1, Profile: "issuer-recovery-dag-v1", Records: map[string]*dagEnvironmentRecord{}}
	if e := w.validateRecoveredDAGDeviceLocked(); !errors.Is(e, ErrDAGProtectedState) {
		t.Fatal("orphan journal accepted", e)
	}
}
func TestDAGEnvironmentStrictJournalShape(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"profile":"p","enrollmentId":"i","enrollmentHash":"h","records":null}`,
		`{"Version":1,"profile":"p","enrollmentId":"i","enrollmentHash":"h","records":{}}`,
		`{"version":1,"version":1,"profile":"p","enrollmentId":"i","enrollmentHash":"h","records":{}}`,
		`{"version":1,"profile":"p","enrollmentId":"i","enrollmentHash":"h","records":{},"extra":0}`,
	} {
		var j dagEnvironmentJournal
		if json.Unmarshal([]byte(raw), &j) == nil {
			t.Fatal("nonexact journal accepted")
		}
	}
	for _, raw := range []string{
		`{"inputHash":"h","contentHash":"h","signed":{},"control":{},"sequence":0,"applied":false,"origin":null}`,
		`{"inputHash":"h","contentHash":"h","signed":{},"control":{},"sequence":0,"applied":false,"extra":0}`,
	} {
		var j dagEnvironmentRecord
		if json.Unmarshal([]byte(raw), &j) == nil {
			t.Fatal("nonexact record accepted")
		}
	}
}
