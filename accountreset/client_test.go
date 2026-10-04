package accountreset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
)

// These tests use only an in-memory transport. They do not listen on a socket,
// send email, run the server, or establish evidence of actual TLS/native/UI use.
type memoryTransport func(*http.Request) (*http.Response, error)

func (f memoryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func answer(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func proofFixture() Proof {
	return Proof{AccountID: "synthetic-account", AccountGeneration: "7", ChallengeID: "synthetic-reset", Token: cryptox.EncodeBase64(bytes.Repeat([]byte{21}, 32))}
}
func memoryClient(t *testing.T, round memoryTransport) *Client {
	t.Helper()
	c, e := New(Config{Endpoint: "https://reset.example.invalid/base"})
	if e != nil {
		t.Fatal(e)
	}
	// Test-only replacement after the production constructor has validated HTTPS.
	c.http.Transport = round
	return c
}
func attemptFixture(t *testing.T, c *Client) *Attempt {
	t.Helper()
	password := []byte("synthetic replacement password")
	a, e := c.NewAttempt(proofFixture(), password, Confirmation)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("password input not consumed")
	}
	t.Cleanup(a.Close)
	return a
}

func TestResetExactInputAndTransportPolicy(t *testing.T) {
	p := proofFixture()
	body, _ := json.Marshal(p)
	if got, e := ParseProof(body); e != nil || got != p {
		t.Fatal("exact proof rejected", e)
	}
	for name, body := range map[string]string{
		"unknown":   `{"accountId":"synthetic-account","accountGeneration":"7","challengeId":"synthetic-reset","token":"` + p.Token + `","email":"synthetic@example.invalid"}`,
		"duplicate": strings.Replace(string(body), `"accountId":`, `"accountId":"other","accountId":`, 1),
		"case":      strings.Replace(string(body), `"accountId"`, `"AccountId"`, 1),
		"null":      strings.Replace(string(body), `"7"`, `null`, 1),
		"number":    strings.Replace(string(body), `"7"`, `7`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseProof([]byte(body)); e == nil {
				t.Fatal("malformed proof accepted")
			}
		})
	}
	for _, generation := range []string{"0", "07", "18446744073709551615", "18446744073709551616"} {
		bad := p
		bad.AccountGeneration = generation
		if _, e := proofGeneration(bad); e == nil {
			t.Fatal("invalid/overflow generation accepted")
		}
	}
	bad := p
	bad.Token += "="
	if _, e := proofGeneration(bad); e == nil {
		t.Fatal("noncanonical token accepted")
	}
	for _, endpoint := range []string{"http://reset.example.invalid", "https://user:pass@reset.example.invalid", "https://reset.example.invalid/?token=secret", "https://reset.example.invalid/#proof", "https://reset.example.invalid/?", "https://reset.example.invalid/base/../other"} {
		if _, e := New(Config{Endpoint: endpoint}); e == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	for _, client := range []*http.Client{
		{Transport: memoryTransport(func(*http.Request) (*http.Response, error) { panic("must not call") })},
		{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
		{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS11}}},
	} {
		if _, e := New(Config{Endpoint: "https://reset.example.invalid", HTTPClient: client}); e == nil {
			t.Fatal("uninspectable or weak TLS accepted")
		}
	}
}

func TestResetRequestAndCommitUseOnlyExactBody(t *testing.T) {
	var routes []string
	c := memoryClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.Scheme != "https" || r.URL.Host != "reset.example.invalid" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unsafe request")
		}
		routes = append(routes, r.URL.Path)
		body, e := io.ReadAll(r.Body)
		if e != nil {
			t.Fatal(e)
		}
		defer clear(body)
		if strings.HasSuffix(r.URL.Path, "/request") {
			var fields map[string]string
			if json.Unmarshal(body, &fields) != nil || len(fields) != 1 || fields["email"] != "synthetic@example.invalid" {
				t.Fatal("wrong request fields")
			}
			return answer(200, `{"accepted":true}`), nil
		}
		var fields map[string]string
		if json.Unmarshal(body, &fields) != nil || len(fields) != 5 {
			t.Fatal("wrong commit fields")
		}
		h := sha256.Sum256([]byte("synthetic replacement password"))
		if fields["accountGeneration"] != "7" || fields["challengeId"] != proofFixture().ChallengeID || fields["token"] != proofFixture().Token || fields["newCredential"] != hex.EncodeToString(h[:]) || fields["confirmation"] != Confirmation {
			t.Fatal("commit changed protocol values")
		}
		if bytes.Contains(body, []byte("synthetic replacement password")) {
			t.Fatal("plaintext password in request")
		}
		return answer(200, `{"accountId":"synthetic-account","accountGeneration":"8","replayed":false}`), nil
	})
	if e := c.RequestProof(context.Background(), "synthetic@example.invalid"); e != nil {
		t.Fatal(e)
	}
	password := []byte("synthetic rejected password")
	if _, e := c.NewAttempt(proofFixture(), password, "NO"); e != ErrInput {
		t.Fatal("confirmation was not mandatory")
	}
	if !bytes.Equal(password, make([]byte, len(password))) || len(routes) != 1 {
		t.Fatal("rejected intent sent or retained password")
	}
	a := attemptFixture(t, c)
	got, e := a.Submit(context.Background())
	if e != nil || got.State != "complete" || got.Source != "commit" || got.Replayed == nil || *got.Replayed {
		t.Fatal("completion invalid", e)
	}
	if len(a.commit) != 0 || len(a.query) != 0 || a.proof.Token != "" {
		t.Fatal("completed attempt retains private payload")
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "trusted") || strings.Contains(string(encoded), "token") {
		t.Fatal("completion grants authority or leaks token")
	}
	if len(routes) != 2 || routes[1] != "/base/v1/accounts/synthetic-account/account-reset/complete" {
		t.Fatal("wrong fixed route")
	}
}

func TestResetUnknownMustQueryAndRetryFrozenPayload(t *testing.T) {
	var commits [][]byte
	statusCalls := 0
	c := memoryClient(t, func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		if strings.HasSuffix(r.URL.Path, "/status") {
			statusCalls++
			var fields map[string]string
			if json.Unmarshal(b, &fields) != nil || len(fields) != 3 || fields["newCredential"] != "" {
				t.Fatal("status gained commit content")
			}
			return answer(200, `{"state":"pending","accountId":"synthetic-account","accountGeneration":"7"}`), nil
		}
		commits = append(commits, b)
		if len(commits) == 1 {
			return nil, errors.New("synthetic remote secret must be redacted")
		}
		return answer(200, `{"accountId":"synthetic-account","accountGeneration":"8","replayed":true}`), nil
	})
	a := attemptFixture(t, c)
	got, e := a.Submit(context.Background())
	if !errors.Is(e, ErrUnknown) || got.State != "unknown" || strings.Contains(e.Error(), "remote secret") {
		t.Fatal("ambiguous submit handling", e)
	}
	if _, e = a.Submit(context.Background()); e != ErrQueryRequired || len(commits) != 1 {
		t.Fatal("unknown implicitly resubmitted", e)
	}
	got, e = a.Query(context.Background())
	if e != nil || got.State != "pending" || len(commits) != 1 || statusCalls != 1 {
		t.Fatal("pending status submitted", e)
	}
	got, e = a.Submit(context.Background())
	if e != nil || got.State != "complete" || got.Replayed == nil || !*got.Replayed || len(commits) != 2 || !bytes.Equal(commits[0], commits[1]) {
		t.Fatal("retry replaced frozen payload", e)
	}
	*got.Replayed = false
	again, e := a.Submit(context.Background())
	if e != nil || again.Replayed == nil || !*again.Replayed || len(commits) != 2 {
		t.Fatal("caller mutated cached completion or caused new write")
	}
}

func TestResetStatusCompleteNeverSubmitsOrGrantsTrust(t *testing.T) {
	commits, queries := 0, 0
	c := memoryClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/complete") {
			commits++
			return answer(504, `{"error":"synthetic-secret"}`), nil
		}
		queries++
		return answer(200, `{"state":"complete","accountId":"synthetic-account","accountGeneration":"8"}`), nil
	})
	a := attemptFixture(t, c)
	if _, e := a.Submit(context.Background()); !errors.Is(e, ErrUnknown) || strings.Contains(e.Error(), "synthetic-secret") {
		t.Fatal("HTTP uncertainty not sanitized", e)
	}
	got, e := a.Query(context.Background())
	if e != nil || got.State != "complete" || got.Source != "status" || got.Replayed != nil {
		t.Fatal("status invented commit response", e)
	}
	if _, e = a.Submit(context.Background()); e != nil || commits != 1 || queries != 1 {
		t.Fatal("complete status caused second commit", e)
	}
	// Cold resolution on a new phone requires only the same original email proof.
	if got, e = c.Query(context.Background(), proofFixture()); e != nil || got.Source != "status" || got.AccountGeneration != "8" || commits != 1 {
		t.Fatal("standalone original proof status failed", e)
	}
}

func TestResetResponseIdentityGenerationAndExactTypes(t *testing.T) {
	p := proofFixture()
	for _, body := range []string{
		`{"state":"pending","accountId":"other","accountGeneration":"7"}`,
		`{"state":"pending","accountId":"synthetic-account","accountGeneration":"8"}`,
		`{"state":"complete","accountId":"synthetic-account","accountGeneration":"7"}`,
		`{"state":"complete","accountId":"synthetic-account","accountGeneration":"9"}`,
		`{"state":"complete","accountId":"synthetic-account","accountGeneration":8}`,
		`{"state":"complete","accountId":"synthetic-account","accountGeneration":"08"}`,
		`{"state":"pending","accountId":"synthetic-account","accountGeneration":"7","trustedDevice":true}`,
		`{"state":"pending","state":"complete","accountId":"synthetic-account","accountGeneration":"8"}`,
		`{"state":"pending","AccountId":"synthetic-account","accountGeneration":"7"}`,
	} {
		if _, e := statusResponse(p, []byte(body)); e != ErrResponse {
			t.Fatal("malformed status accepted", e)
		}
	}
	for _, body := range []string{
		`{"accountId":"other","accountGeneration":"8","replayed":false}`,
		`{"accountId":"synthetic-account","accountGeneration":"7","replayed":false}`,
		`{"accountId":"synthetic-account","accountGeneration":"9","replayed":false}`,
		`{"accountId":"synthetic-account","accountGeneration":"8"}`,
		`{"accountId":"synthetic-account","accountGeneration":"8","replayed":null}`,
		`{"accountId":"synthetic-account","accountGeneration":"8","replayed":"false"}`,
		`{"accountId":"synthetic-account","accountGeneration":"8","replayed":false,"token":"secret"}`,
	} {
		if _, e := completeResponse(p, []byte(body)); e != ErrResponse {
			t.Fatal("malformed completion accepted", e)
		}
	}
}

func TestResetCloseCancelsAndRejectsLateCompletion(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	c := memoryClient(t, func(r *http.Request) (*http.Response, error) {
		once.Do(func() { close(entered) })
		<-r.Context().Done()
		<-release
		return answer(200, `{"accountId":"synthetic-account","accountGeneration":"8","replayed":false}`), nil
	})
	a := attemptFixture(t, c)
	done := make(chan error, 1)
	go func() { _, e := a.Submit(context.Background()); done <- e }()
	<-entered
	if _, e := a.Query(context.Background()); e != ErrBusy {
		t.Fatal("concurrent request admitted", e)
	}
	a.Close()
	close(release)
	if e := <-done; e != ErrClosed {
		t.Fatal("retired request delivered completion", e)
	}
	if len(a.commit) != 0 || len(a.query) != 0 || a.proof.Token != "" {
		t.Fatal("closed attempt retained payload")
	}
	if _, e := a.Submit(context.Background()); e != ErrClosed {
		t.Fatal("closed attempt reopened", e)
	}
}

func TestResetCallerCancellationKeepsOriginalAttemptUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := memoryClient(t, func(r *http.Request) (*http.Response, error) {
		cancel()
		// A deliberately late in-memory response must not override caller retirement.
		return answer(200, `{"accountId":"synthetic-account","accountGeneration":"8","replayed":false}`), nil
	})
	a := attemptFixture(t, c)
	got, err := a.Submit(ctx)
	if !errors.Is(err, ErrUnknown) || got.State != "unknown" {
		t.Fatal("cancelled operation delivered completion", err)
	}
	if _, err = a.Submit(context.Background()); err != ErrQueryRequired {
		t.Fatal("cancelled submit admitted a retry without query", err)
	}
}
