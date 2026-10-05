package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

type memoryJournal struct {
	data []byte
	fail bool
}

func (j *memoryJournal) Load() ([]byte, error) {
	if j.data == nil {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(j.data), nil
}
func (j *memoryJournal) Save(data []byte) error {
	if j.fail {
		return errors.New("synthetic persistence unavailable")
	}
	j.data = bytes.Clone(data)
	return nil
}

type writeFixture struct {
	mu            sync.Mutex
	crypto        *cryptoFixture
	engine        *localstate.Engine
	server        *httptest.Server
	client        *Client
	events        []Event
	receipts      map[string]MutationStatus
	seq           uint64
	posts         int
	lose          bool
	reject        bool
	rejectedGrant *SignedGrant
	badReceipt    bool
	afterPost     func()
	journal       *memoryJournal
}

func newWriteFixture(t *testing.T) *writeFixture {
	t.Helper()
	f := &writeFixture{crypto: newCryptoFixture(t), engine: testEngine(t), receipts: map[string]MutationStatus{}, seq: 1, journal: &memoryJournal{}}
	f.events = []Event{f.crypto.event(t, 1, "initial")}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/mutation-status"):
			id := r.URL.Query().Get("idempotencyKey")
			status, ok := f.receipts[id]
			if !ok {
				status = MutationStatus{IdempotencyKey: id}
			}
			if f.badReceipt && status.Accepted {
				status.ContentHash = strings.Repeat("0", 64)
			}
			_ = json.NewEncoder(w).Encode(status)
		case r.Method == "POST":
			if f.reject {
				if f.rejectedGrant != nil {
					f.crypto.grant = *f.rejectedGrant
					f.seq++
					f.rejectedGrant = nil
				}
				w.WriteHeader(403)
				_, _ = io.WriteString(w, `{"error":"write_forbidden"}`)
				return
			}
			var signed SignedMutation
			_ = json.NewDecoder(r.Body).Decode(&signed)
			if cryptox.VerifyMutation(cryptox.SignedMutation{Mutation: signed.Mutation, Signature: signed.Signature}, f.crypto.devicePublic) != nil {
				t.Error("invalid device signature")
			}
			if _, ok := f.receipts[signed.Mutation.IdempotencyKey]; ok {
				t.Error("alreadyaccepted mutation resubmitted")
			}
			if len(f.journal.data) == 0 {
				t.Error("mutation sent before durable journal")
			}
			if bytes.Contains(f.journal.data, []byte("new-shared-secret")) {
				t.Error("plaintext stored in journal")
			}
			f.posts++
			f.seq++
			hash, err := signedContentHash(signed)
			check(t, err)
			f.receipts[signed.Mutation.IdempotencyKey] = MutationStatus{IdempotencyKey: signed.Mutation.IdempotencyKey, Accepted: true, Sequence: f.seq, ContentHash: hash}
			authority := f.crypto.grant
			f.events = append(f.events, Event{Sequence: f.seq, Mutation: signed, Authorization: &authority})
			if f.afterPost != nil {
				f.afterPost()
			}
			if f.lose {
				f.lose = false
				w.WriteHeader(504)
				_, _ = io.WriteString(w, `{"error":"request_rejected"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(Acceptance{Sequence: f.seq})
		default:
			pull := f.crypto.pull(f.seq)
			pull.Full = false
			if r.URL.Query().Get("scope") == "authorizations" {
				pull.Scope = "authorizations"
			} else {
				after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
				for _, event := range f.events {
					if event.Sequence > after {
						pull.Events = append(pull.Events, event)
					}
				}
			}
			_ = json.NewEncoder(w).Encode(pull)
		}
	}))
	t.Cleanup(f.server.Close)
	f.client = testClient(t, f.server, f.engine, f.crypto.verifier)
	return f
}
func (f *writeFixture) writer(t *testing.T) *Writer {
	t.Helper()
	writer, err := NewWriter("acct", 1, "dev", f.engine.State().SessionEpoch, f.crypto.devicePrivate, f.journal)
	check(t, err)
	t.Cleanup(writer.Close)
	return writer
}
func TestWriterRealEncryptedPutDeleteImportAndSameFlow(t *testing.T) {
	f := newWriteFixture(t)
	writer := f.writer(t)
	result, err := writer.Execute(context.Background(), f.client, WriteRequest{ID: "request-put", Operation: "put", EnvironmentID: "env", Name: "TOKEN", Value: "new-shared-secret"})
	check(t, err)
	if !result.Applied || result.Accepted != 1 || result.Sequences[0] != 2 || f.engine.State().Cloud.Environments["env"].Values["TOKEN"] != "new-shared-secret" {
		t.Fatal(result)
	}
	result, err = writer.Execute(context.Background(), f.client, WriteRequest{ID: "request-import", Operation: "import", EnvironmentID: "env", Values: map[string]string{"ADDED": "synthetic-selected", "EMPTY": ""}})
	check(t, err)
	if result.Total != 2 || !result.Applied || f.engine.State().Cloud.Environments["env"].Values["ADDED"] != "synthetic-selected" {
		t.Fatal(result)
	}
	result, err = writer.Execute(context.Background(), f.client, WriteRequest{ID: "request-delete", Operation: "delete", EnvironmentID: "env", Name: "TOKEN"})
	check(t, err)
	if _, exists := f.engine.State().Cloud.Environments["env"].Values["TOKEN"]; exists || !result.Applied {
		t.Fatal("delete failed verified flow")
	}
}
func TestWriterLostAcceptanceSurvivesRestartAndLaterOverwrite(t *testing.T) {
	f := newWriteFixture(t)
	f.lose = true
	writer := f.writer(t)
	result, err := writer.Execute(context.Background(), f.client, WriteRequest{ID: "lost-1", Operation: "put", EnvironmentID: "env", Name: "TOKEN", Value: "new-shared-secret"})
	if !errors.Is(err, ErrWritePending) || result.Applied || f.engine.State().Cloud.Environments["env"].Values["TOKEN"] != "initial" {
		t.Fatal("uncertain response optimistically applied", result, err)
	}
	writer.Close()
	f.mu.Lock()
	f.seq++
	f.events = append(f.events, f.crypto.event(t, f.seq, "later-wins"))
	f.mu.Unlock()
	restarted := f.writer(t)
	result, err = restarted.Execute(context.Background(), f.client, WriteRequest{ID: "lost-1", Operation: "retry"})
	check(t, err)
	if !result.Applied || result.Sequences[0] != 2 || f.posts != 1 || f.engine.State().Cloud.Environments["env"].Values["TOKEN"] != "later-wins" {
		t.Fatal("retry guessed current value or generated new write", result, f.posts)
	}
	if _, err = restarted.Execute(context.Background(), f.client, WriteRequest{ID: "lost-1", Operation: "put", EnvironmentID: "env", Name: "TOKEN", Value: "different-input"}); !errors.Is(err, ErrWriteConflict) {
		t.Fatal("same ID changed input", err)
	}
}
func TestWriterPersistenceFailureNeverSubmitsAndRetryRepersists(t *testing.T) {
	f := newWriteFixture(t)
	writer := f.writer(t)
	f.journal.fail = true
	request := WriteRequest{ID: "durable-1", Operation: "put", EnvironmentID: "env", Name: "TOKEN", Value: "new-shared-secret"}
	if _, err := writer.Execute(context.Background(), f.client, request); !errors.Is(err, ErrWriteJournal) || f.posts != 0 {
		t.Fatal("journal failure submitted", err)
	}
	if _, err := writer.Execute(context.Background(), f.client, request); !errors.Is(err, ErrWriteJournal) || f.posts != 0 {
		t.Fatal("inmemory retry bypassed journal", err)
	}
	f.journal.fail = false
	_, err := writer.Execute(context.Background(), f.client, request)
	check(t, err)
}
func TestWriterROPauseAndConcurrentDowngradeDoNotWrite(t *testing.T) {
	for _, kind := range []string{"ro", "pause", "concurrent"} {
		t.Run(kind, func(t *testing.T) {
			f := newWriteFixture(t)
			writer := f.writer(t)
			if kind == "pause" {
				check(t, f.engine.SetPaused(true))
			}
			if kind == "ro" {
				g := f.crypto.grant.Grant
				g.Role = "ro"
				f.crypto.grant = f.crypto.resignGrant(t, g)
			}
			if kind == "concurrent" {
				f.reject = true
				g := f.crypto.grant.Grant
				g.Role = "none"
				g.Envelope = ""
				g.GrantGeneration = "2"
				g.IdempotencyKey = "revoke-2"
				changed := f.crypto.resignGrant(t, g)
				f.rejectedGrant = &changed
			}
			result, err := writer.Execute(context.Background(), f.client, WriteRequest{ID: "denied-1", Operation: "put", EnvironmentID: "env", Name: "TOKEN", Value: "new-shared-secret"})
			if kind == "concurrent" && (len(f.engine.State().Cloud.Environments) != 0 || !writer.log.Records[0].Canceled) {
				t.Fatal("concurrent revoke kept pending cache/cipher")
			}
			if err == nil || result.Applied || f.posts != 0 {
				t.Fatal("nonwritable request submitted", result, err)
			}
		})
	}
}
func TestWriterRejectsReceiptTamperAndAccountEpochMismatch(t *testing.T) {
	f := newWriteFixture(t)
	f.lose = true
	writer := f.writer(t)
	_, err := writer.Execute(context.Background(), f.client, WriteRequest{ID: "tamper-1", Operation: "put", EnvironmentID: "env", Name: "TOKEN", Value: "new-shared-secret"})
	if !errors.Is(err, ErrWritePending) {
		t.Fatal(err)
	}
	f.badReceipt = true
	if _, err = writer.Execute(context.Background(), f.client, WriteRequest{ID: "tamper-1", Operation: "retry"}); !errors.Is(err, ErrWriteConflict) {
		t.Fatal("unbound receipt accepted", err)
	}
	if other, err := NewWriter("another", 1, "dev", 0, f.crypto.devicePrivate, f.journal); err == nil {
		other.Close()
		t.Fatal("crossaccount journal loaded")
	}
	check(t, f.engine.Logout())
	safe, err := NewWriter("acct", 1, "dev", f.engine.State().SessionEpoch, f.crypto.devicePrivate, f.journal)
	check(t, err)
	defer safe.Close()
	if !safe.log.Records[0].Canceled || safe.log.Records[0].Items[0].Mutation.Mutation.Payload != "" {
		t.Fatal("old epoch pending ciphertext restored")
	}
	if _, err = New(Config{Endpoint: f.server.URL, HTTPClient: f.server.Client(), AccountID: "acct", AccountGeneration: 1, DeviceID: "dev", Token: cryptox.EncodeBase64(make([]byte, 32)), Engine: f.engine, Verifier: f.crypto.verifier}); !errors.Is(err, localstate.ErrLocalSession) {
		t.Fatal("logout tombstone allowed new ordinary client", err)
	}
}
func TestWriterCancelPendingClearsCipherAndCannotRetry(t *testing.T) {
	f := newWriteFixture(t)
	f.lose = true
	writer := f.writer(t)
	_, err := writer.Execute(context.Background(), f.client, WriteRequest{ID: "cancel-1", Operation: "put", EnvironmentID: "env", Name: "TOKEN", Value: "new-shared-secret"})
	if !errors.Is(err, ErrWritePending) {
		t.Fatal(err)
	}
	cipher := writer.log.Records[0].Items[0].Mutation.Mutation.Payload
	check(t, writer.CancelPending(f.engine.State().SessionEpoch))
	if bytes.Contains(f.journal.data, []byte(cipher)) {
		t.Fatal("cancel retained pending ciphertext")
	}
	restarted := f.writer(t)
	if _, err = restarted.Execute(context.Background(), f.client, WriteRequest{ID: "cancel-1", Operation: "retry"}); !errors.Is(err, ErrWritePermission) {
		t.Fatal("canceled item retried", err)
	}
	if f.posts != 1 {
		t.Fatal("canceled item generated another write")
	}
}
