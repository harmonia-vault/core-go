package mobileworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestDAGBusinessRestrictedOriginalRejectsBeforeNetwork(t *testing.T) {
	_, w, _ := b3bConfirmedFixture(t)
	defer w.Close()
	var requests atomic.Int32
	w.http = &http.Client{Transport: b3bRejectTransport{calls: &requests}}
	if _, e := w.SetDAGVariable(context.Background(), "synthetic-env", "TOKEN", "SYNTHETIC_VALUE", "synthetic-id"); !errors.Is(e, ErrNotTrusted) {
		t.Fatal(e)
	}
	if _, e := w.PendingDAGWrites(); !errors.Is(e, ErrNotTrusted) {
		t.Fatal(e)
	}
	if _, e := w.RetryDAGWrite(context.Background(), "synthetic-id"); !errors.Is(e, ErrNotTrusted) {
		t.Fatal(e)
	}
	if requests.Load() != 0 {
		t.Fatal("unapplied original used network")
	}
	w.state.DAGWrites = &dagWriteJournal{Version: 1, Profile: "issuer-recovery-dag-v1", EnrollmentID: "synthetic-id", EnrollmentHash: "bad", Log: []byte("{}")}
	if e := w.validateRecoveredDAGDeviceLocked(); !errors.Is(e, ErrDAGProtectedState) {
		t.Fatal("orphan business journal accepted", e)
	}
}

func TestDAGBusinessJournalStrictWrapper(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"profile":"p","enrollmentId":"i","enrollmentHash":"h","log":"e30=","extra":0}`,
		`{"Version":1,"profile":"p","enrollmentId":"i","enrollmentHash":"h","log":"e30="}`,
		`{"version":1,"profile":"p","enrollmentId":"i","enrollmentHash":"h","log":null}`,
		`{"version":1,"version":1,"profile":"p","enrollmentId":"i","enrollmentHash":"h","log":"e30="}`,
	} {
		var journal dagWriteJournal
		if json.Unmarshal([]byte(raw), &journal) == nil {
			t.Fatal("nonexact wrapper accepted")
		}
	}
}
