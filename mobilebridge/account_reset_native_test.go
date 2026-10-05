package mobilebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/accountreset"
)

type resetBusinessFixture struct {
	queries, posts, prepares int
	queryError, postError    error
	state                    string
	onPost                   func(context.Context)
}

func (f *resetBusinessFixture) Query(context.Context) (accountreset.Outcome, error) {
	f.queries++
	if f.queryError != nil {
		return accountreset.Outcome{}, f.queryError
	}
	g := "7"
	if f.state == "complete" {
		g = "8"
	}
	return accountreset.Outcome{State: f.state, AccountID: "synthetic-account", AccountGeneration: g, Source: "status"}, nil
}
func (f *resetBusinessFixture) Submit(ctx context.Context) (accountreset.Outcome, error) {
	f.posts++
	if f.onPost != nil {
		f.onPost(ctx)
	}
	if f.postError != nil {
		return accountreset.Outcome{}, f.postError
	}
	f.state = "complete"
	return f.Query(ctx)
}
func (*resetBusinessFixture) Close() {}
func resetFixture(t *testing.T) (*NativeAccountReset, *resetBusinessFixture) {
	t.Helper()
	f := &resetBusinessFixture{state: "pending"}
	r := &NativeAccountReset{endpoint: "https://synthetic.example.invalid", namespace: "synthetic-slot", proof: accountreset.Proof{AccountID: "synthetic-account", AccountGeneration: "7"}, now: time.Now}
	r.query = func(ctx context.Context, _ accountreset.Proof) (accountreset.Outcome, error) { return f.Query(ctx) }
	r.prepare = func(_ accountreset.Proof, _ []byte, s string) (resetAttempt, error) {
		if s != accountreset.Confirmation {
			return nil, errInput
		}
		f.prepares++
		return f, nil
	}
	t.Cleanup(r.Close)
	return r, f
}
func prepareReset(t *testing.T, r *NativeAccountReset) {
	t.Helper()
	if _, e := r.Query(); e != nil {
		t.Fatal(e)
	}
	b := []byte("only-synthetic-password")
	if e := r.Prepare(b, accountreset.Confirmation); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("password input survived")
	}
}

type resetCleanupFixture struct {
	clear          func() error
	check          func() error
	clears, checks int
}

func (c *resetCleanupFixture) ClearAndReacquireEmpty() error {
	c.clears++
	if c.clear != nil {
		return c.clear()
	}
	return nil
}
func (c *resetCleanupFixture) CheckEmpty() error {
	c.checks++
	if c.check != nil {
		return c.check()
	}
	return nil
}

func TestNativeAccountResetQueryBeforeCleanupAndFrozenRetry(t *testing.T) {
	r, f := resetFixture(t)
	if e := r.Prepare([]byte("synthetic"), accountreset.Confirmation); e == nil {
		t.Fatal("prepared without proof query")
	}
	if _, e := r.BeginCompletion(); e == nil {
		t.Fatal("cold owner obtained submission")
	}
	prepareReset(t, r)
	if e := r.Prepare([]byte("replacement"), accountreset.Confirmation); e == nil || f.prepares != 1 {
		t.Fatal("replaced original payload")
	}
	f.queryError = accountreset.ErrResponse
	if _, e := r.BeginCompletion(); e == nil {
		t.Fatal("invalid proof accepted")
	}
	if f.posts != 0 {
		t.Fatal("query posted")
	}
	f.queryError = nil
	p, e := r.BeginCompletion()
	if e != nil {
		t.Fatal(e)
	}
	c := &resetCleanupFixture{clear: func() error { return errors.New("synthetic physical deletion failure") }}
	if _, e = p.Complete(c); e == nil || f.posts != 0 {
		t.Fatal("cleanup failure posted")
	}
	p, e = r.BeginCompletion()
	if e != nil {
		t.Fatal(e)
	}
	f.postError = accountreset.ErrUnknown
	c = &resetCleanupFixture{}
	if _, e = p.Complete(c); !errors.Is(e, accountreset.ErrUnknown) {
		t.Fatal(e)
	}
	if _, e = p.Complete(c); e == nil || f.posts != 1 {
		t.Fatal("single-use ticket reposted")
	}
	f.postError = nil
	p, e = r.BeginCompletion()
	if e != nil {
		t.Fatal(e)
	}
	result, e := p.Complete(c)
	if e != nil {
		t.Fatal(e)
	}
	if f.posts != 2 || f.prepares != 1 || !strings.Contains(result, `"trustedDevice":false`) || !strings.Contains(result, `"accountGeneration":"8"`) {
		t.Fatal("retry changed owner or granted trust")
	}
}
func TestNativeAccountResetCompleteStatusStillNeedsCleanupButNeverPosts(t *testing.T) {
	r, f := resetFixture(t)
	prepareReset(t, r)
	f.state = "complete"
	p, e := r.BeginCompletion()
	if e != nil {
		t.Fatal(e)
	}
	c := &resetCleanupFixture{}
	if _, e = p.Complete(c); e != nil {
		t.Fatal(e)
	}
	if c.clears != 1 || c.checks != 2 || f.posts != 0 {
		t.Fatal("status bypassed native cleanup or submitted")
	}
}

func TestNativeAccountResetColdQueryCannotAcquireSubmission(t *testing.T) {
	r, f := resetFixture(t)
	r.queryOnly = true
	if _, e := r.Query(); e != nil {
		t.Fatal(e)
	}
	if e := r.Prepare([]byte("changed-synthetic-password"), accountreset.Confirmation); e == nil {
		t.Fatal("cold owner prepared replacement")
	}
	if _, e := r.BeginCompletion(); e == nil {
		t.Fatal("cold owner obtained completion")
	}
	if f.prepares != 0 || f.posts != 0 {
		t.Fatal("cold query wrote")
	}
}

func TestNativeAccountResetCloseCancelsPendingQuery(t *testing.T) {
	r, _ := resetFixture(t)
	started := make(chan struct{})
	done := make(chan error, 1)
	r.query = func(ctx context.Context, _ accountreset.Proof) (accountreset.Outcome, error) {
		close(started)
		<-ctx.Done()
		return accountreset.Outcome{State: "pending"}, nil
	}
	go func() { _, e := r.Query(); done <- e }()
	<-started
	r.Close()
	select {
	case e := <-done:
		if !errors.Is(e, accountreset.ErrClosed) {
			t.Fatal("late query accepted", e)
		}
	case <-time.After(time.Second):
		t.Fatal("query not cancelled")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.verified || r.proof.AccountID != "" {
		t.Fatal("closed owner repopulated")
	}
}
func TestNativeAccountResetClosedExpiredAndChangedEmptySlotBlock(t *testing.T) {
	for _, mode := range []string{"closed", "expired", "empty-conflict", "close-during-cleanup", "late-post"} {
		t.Run(mode, func(t *testing.T) {
			r, f := resetFixture(t)
			prepareReset(t, r)
			p, e := r.BeginCompletion()
			if e != nil {
				t.Fatal(e)
			}
			c := &resetCleanupFixture{}
			switch mode {
			case "closed":
				r.Close()
			case "expired":
				r.now = func() time.Time { return p.expires }
			case "empty-conflict":
				c.check = func() error { return errors.New("synthetic slot replaced") }
			case "close-during-cleanup":
				c.clear = func() error { r.Close(); return nil }
			case "late-post":
				f.onPost = func(context.Context) { r.Close() }
			}
			if _, e = p.Complete(c); e == nil {
				t.Fatal("retired result accepted")
			}
			want := 0
			if mode == "late-post" {
				want = 1
			}
			if f.posts != want {
				t.Fatal("unexpected post", f.posts)
			}
		})
	}
}

func resetSealedWorkflow(t *testing.T, account, generation string) (*VaultWorkflow, *atomicSealedFixture) {
	t.Helper()
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(d.Close)
	s := &atomicSealedFixture{}
	v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic-slot", nil, nil, s)
	if e != nil {
		t.Fatal(e)
	}
	b, e := v.workflow.ExportProtectedState()
	if e != nil {
		t.Fatal(e)
	}
	var plain map[string]json.RawMessage
	if e = json.Unmarshal(b, &plain); e != nil {
		t.Fatal(e)
	}
	clear(b)
	plain["accountId"], _ = json.Marshal(account)
	plain["accountGeneration"], _ = json.Marshal(generation)
	b, e = json.Marshal(plain)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(b)
	if e = v.saveCAS(v.protectedSHA256, b); e != nil {
		t.Fatal(e)
	}
	v.Close()
	v, e = d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic-slot", s.read(), nil, s)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(v.Close)
	return v, s
}
func TestNativeAccountResetLogoutUsesAEADBindingAndFullState(t *testing.T) {
	for _, mode := range []string{"matched-untrusted", "other-account", "new-generation", "namespace", "endpoint", "stale-sealed"} {
		t.Run(mode, func(t *testing.T) {
			account, generation := "synthetic-account", "7"
			if mode == "other-account" {
				account = "other-account"
			}
			if mode == "new-generation" {
				generation = "8"
			}
			v, s := resetSealedWorkflow(t, account, generation)
			r, f := resetFixture(t)
			prepareReset(t, r)
			if mode == "namespace" {
				r.namespace = "other-slot"
			}
			if mode == "endpoint" {
				r.endpoint = "https://other.example.invalid"
			}
			if mode == "stale-sealed" {
				s.mu.Lock()
				s.packet[len(s.packet)-1] ^= 1
				s.mu.Unlock()
			}
			before := s.read()
			p, e := r.BeginCompletion()
			if e != nil {
				t.Fatal(e)
			}
			if e = p.LogoutMatchedWorkflow(v); e == nil {
				t.Fatal("logout allowed outside cleanup callback")
			}
			c := &resetCleanupFixture{clear: func() error { return p.LogoutMatchedWorkflow(v) }}
			_, e = p.Complete(c)
			if mode == "matched-untrusted" {
				if e != nil || !v.RequiresDeviceDeletion() || f.posts != 1 || !v.binding.AccountClosed {
					t.Fatal("matching untrusted local slot rejected", e)
				}
			} else {
				if e == nil || f.posts != 0 || v.RequiresDeviceDeletion() || !bytes.Equal(before, s.read()) {
					t.Fatal("mismatched local account altered")
				}
			}
		})
	}
}

func TestNativeAccountResetRejectsInternalProofAsUserInput(t *testing.T) {
	input := []byte(`{"accountId":"synthetic-account","accountGeneration":"1","challengeId":"old-challenge","token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	owner, err := NewNativeAccountReset("https://synthetic.example.invalid", "synthetic-slot", input, nil)
	if err == nil || owner != nil {
		t.Fatal("old proof bypassed email/code exchange")
	}
	if !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("rejected input was not cleared")
	}
}
