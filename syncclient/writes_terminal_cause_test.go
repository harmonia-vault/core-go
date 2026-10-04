package syncclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type terminalFailureJournal struct {
	mu      sync.Mutex
	journal memoryJournal
}

func (j *terminalFailureJournal) Load() ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.journal.Load()
}
func (j *terminalFailureJournal) Save(b []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.journal.Save(b)
}
func (j *terminalFailureJournal) failAfterDurable() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	present := len(j.journal.data) > 0
	j.journal.fail = true
	return present
}

// Journal失败不能覆盖Submit后Pull或403后授权刷新已经明确收到的终态失权。
func TestWriterJournalFailureRetainsReceivedTerminalCause(t *testing.T) {
	for _, accepted := range []bool{true, false} {
		t.Run(map[bool]string{true: "accepted-pull", false: "denied-authorization-refresh"}[accepted], func(t *testing.T) {
			f := newCryptoFixture(t)
			defer f.verifier.Close()
			engine := testEngine(t)
			journal := &terminalFailureJournal{}
			var posted atomic.Bool
			var posts atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/mutations") {
					posts.Add(1)
					var packet SignedMutation
					if json.NewDecoder(r.Body).Decode(&packet) != nil {
						t.Error("synthetic mutation decode failed")
					}
					if !journal.failAfterDurable() {
						t.Error("POST before journal")
					}
					posted.Store(true)
					if accepted {
						_ = json.NewEncoder(w).Encode(Acceptance{Sequence: 2})
					} else {
						w.WriteHeader(403)
						_, _ = w.Write([]byte(`{"error":"write_forbidden"}`))
					}
					return
				}
				if posted.Load() {
					w.WriteHeader(403)
					_, _ = w.Write([]byte(`{"error":"device_untrusted"}`))
					return
				}
				if strings.HasSuffix(r.URL.Path, "/mutation-status") {
					_ = json.NewEncoder(w).Encode(MutationStatus{IdempotencyKey: r.URL.Query().Get("idempotencyKey")})
					return
				}
				after := r.URL.Query().Get("after")
				p := f.pull(1)
				if after == "0" {
					p.Events = []Event{f.event(t, 1, "SYNTHETIC")}
				}
				_ = json.NewEncoder(w).Encode(p)
			}))
			defer srv.Close()
			client := testClient(t, srv, engine, f.verifier)
			writer, e := NewWriter("acct", 1, "dev", engine.State().SessionEpoch, f.devicePrivate, journal)
			check(t, e)
			defer writer.Close()
			out, e := writer.Execute(context.Background(), client, WriteRequest{ID: "terminal-cause", Operation: "put", EnvironmentID: "env", Name: "TOKEN", Value: "SYNTHETIC"})
			if !errors.Is(e, ErrWriteJournal) || !errors.Is(e, ErrTrustInvalidated) || out.Applied || posts.Load() != 1 || !engine.State().AccountClosed {
				t.Fatalf("terminal cause or journal failure lost: %v", e)
			}
			if accepted {
				if out.Accepted != 1 || !errors.Is(e, ErrAcceptedNotApplied) {
					t.Fatal("accepted receipt lost")
				}
			} else if out.Accepted != 0 {
				t.Fatal("denied request counted accepted")
			}
		})
	}
}
