package syncclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

type volatileStore struct{ state localstate.State }

func (s *volatileStore) Load() (localstate.State, error)   { return s.state, nil }
func (s *volatileStore) Save(state localstate.State) error { s.state = state; return nil }

type acceptVerifier struct{ fail bool }

func (v acceptVerifier) VerifyPull(_ context.Context, pull Pull, _ localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	if v.fail {
		return localstate.CloudSnapshot{}, errors.New("synthetic invalid signature")
	}
	return localstate.CloudSnapshot{AccountID: "acct", AccountGeneration: 1, Sequence: pull.Sequence, Environments: map[string]localstate.Environment{"env": {ID: "env", KeyVersion: 1, GrantGeneration: 1, Role: localstate.ReadWrite, Values: map[string]string{"TOKEN": "verified-only"}}}}, nil
}
func testEngine(t *testing.T) *localstate.Engine {
	t.Helper()
	e, err := localstate.New(&volatileStore{state: localstate.EmptyState()})
	check(t, err)
	return e
}
func testClient(t *testing.T, server *httptest.Server, engine *localstate.Engine, verifier Verifier) *Client {
	t.Helper()
	client, err := New(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: "acct", AccountGeneration: 1, DeviceID: "dev", Token: cryptox.EncodeBase64(make([]byte, 32)), Engine: engine, Verifier: verifier, Now: func() time.Time { return fixedNow }})
	check(t, err)
	return client
}
func transportMutation() SignedMutation {
	return SignedMutation{Mutation: Mutation{AccountID: "acct", AccountGeneration: "1", DeviceID: "dev", EnvironmentID: "env", Operation: "put", IdempotencyKey: "write-1", Name: "TOKEN"}, Signature: "synthetic-wire-test"}
}
func TestSubmitUpdatesOnlyAfterVerifiedPull(t *testing.T) {
	engine := testEngine(t)
	requests := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Harmonia-Device-Id") != "dev" || r.Header.Get("X-Harmonia-Account-Generation") != "1" || r.Header.Get("Cache-Control") != "no-store" {
			t.Error("unbound or cacheable request")
		}
		if len(engine.State().Cloud.Environments) != 0 {
			t.Error("optimistic state changed before pull")
		}
		if r.Method == "POST" {
			_ = json.NewEncoder(w).Encode(Acceptance{Sequence: 1})
		} else {
			_ = json.NewEncoder(w).Encode(Pull{AccountID: "acct", AccountGeneration: "1", Sequence: 1})
		}
	}))
	defer server.Close()
	client := testClient(t, server, engine, acceptVerifier{})
	result, err := client.Submit(context.Background(), transportMutation())
	check(t, err)
	if !result.Applied || result.Accepted.Sequence != 1 || engine.State().Cloud.Environments["env"].Values["TOKEN"] != "verified-only" || len(requests) != 2 {
		t.Fatal(result, requests)
	}
}
func TestAcceptedPullFailurePreservesLocalAuthority(t *testing.T) {
	engine := testEngine(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_ = json.NewEncoder(w).Encode(Acceptance{Sequence: 4})
		} else {
			http.Error(w, "synthetic revoked", 403)
		}
	}))
	defer server.Close()
	client := testClient(t, server, engine, acceptVerifier{})
	result, err := client.Submit(context.Background(), transportMutation())
	if !errors.Is(err, ErrAcceptedNotApplied) || result.Accepted.Sequence != 4 || result.Applied || engine.State().Cloud.Sequence != 0 {
		t.Fatal(result, err)
	}
}
func TestPullVerificationFailureDoesNotApply(t *testing.T) {
	engine := testEngine(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Pull{AccountID: "acct", AccountGeneration: "1", Sequence: 1})
	}))
	defer server.Close()
	client := testClient(t, server, engine, acceptVerifier{fail: true})
	if _, err := client.Pull(context.Background()); err == nil || engine.State().Cloud.Sequence != 0 {
		t.Fatal("failed verification became authority")
	}
}
func TestHTTPAndCredentialURLsRejected(t *testing.T) {
	for _, endpoint := range []string{"http://example.test", "https://user:password@example.test", "https://example.test?token=secret", "https://example.test#token"} {
		if _, err := New(Config{Endpoint: endpoint, Engine: testEngine(t), Verifier: acceptVerifier{}}); err == nil {
			t.Fatal("unsafe URL accepted", endpoint)
		}
	}
}
func TestRedirectDoesNotForwardSession(t *testing.T) {
	var reached atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := testClient(t, source, testEngine(t), acceptVerifier{})
	if _, err := client.Pull(context.Background()); err == nil || reached.Load() != 0 {
		t.Fatal("session redirect followed")
	}
}
func TestUnboundLoginMustProveDevicePossession(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	loginToken := cryptox.EncodeBase64(make([]byte, 32))
	boundToken := cryptox.EncodeBase64(append([]byte{1}, make([]byte, 31)...))
	nonce := cryptox.EncodeBase64(make([]byte, 32))
	expires := fixedNow.Add(2 * time.Minute).Unix()
	proof, err := cryptox.NewDeviceSessionProof("acct", "1", "dev", loginToken, "challenge-1", nonce, fmtInt(expires))
	check(t, err)
	payload, err := proof.SigningBytes()
	check(t, err)
	var fields []string
	_ = json.Unmarshal(payload, &fields)
	var consumed bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "device-challenges"):
			_ = json.NewEncoder(w).Encode(DeviceChallenge{ChallengeID: "challenge-1", Nonce: nonce, ExpiresAt: expires, SigningPayload: fields})
		case strings.HasSuffix(r.URL.Path, "device-sessions"):
			var request struct {
				ChallengeID string `json:"challengeId"`
				Signature   string `json:"signature"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if consumed || cryptox.VerifyDeviceSessionProof(proof, request.Signature, public) != nil {
				http.Error(w, "invalid proof", 403)
				return
			}
			consumed = true
			_ = json.NewEncoder(w).Encode(DeviceSession{Token: boundToken, ExpiresAt: fixedNow.Add(time.Hour).Unix()})
		default:
			if r.Header.Get("Authorization") != "Bearer "+boundToken {
				http.Error(w, "unbound login", 403)
				return
			}
			_ = json.NewEncoder(w).Encode(Pull{AccountID: "acct", AccountGeneration: "1", Sequence: 1})
		}
	}))
	defer server.Close()
	client := testClient(t, server, testEngine(t), acceptVerifier{})
	if _, err = client.Pull(context.Background()); err == nil {
		t.Fatal("login token alone read trusted device data")
	}
	bound, err := client.BindDevice(context.Background(), private)
	check(t, err)
	_, err = bound.Pull(context.Background())
	check(t, err)
	if _, err = client.Pull(context.Background()); err == nil {
		t.Fatal("binding mutated login client token")
	}
}
func TestBindDeviceRejectsUnboundChallengeWithoutSigning(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	var submitted atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "device-sessions") {
			submitted.Add(1)
		}
		_ = json.NewEncoder(w).Encode(DeviceChallenge{ChallengeID: "challenge-1", Nonce: cryptox.EncodeBase64(make([]byte, 32)), ExpiresAt: fixedNow.Add(time.Minute).Unix(), SigningPayload: []string{"unrelated operation"}})
	}))
	defer server.Close()
	client := testClient(t, server, testEngine(t), acceptVerifier{})
	if _, err = client.BindDevice(context.Background(), private); err == nil || submitted.Load() != 0 {
		t.Fatal("blind signing accepted")
	}
}
func TestNewEnvironmentAutomaticallyTriggersFullCatchup(t *testing.T) {
	f := newCryptoFixture(t)
	engine := testEngine(t)
	check(t, engine.AcceptSnapshot(localstate.CloudSnapshot{AccountID: "acct", AccountGeneration: 1, Sequence: 10, Environments: map[string]localstate.Environment{}}, fixedNow))
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		pull := f.pull(11)
		if r.URL.Query().Get("after") == "0" {
			pull.Events = []Event{f.event(t, 1, "old-env-data")}
		}
		_ = json.NewEncoder(w).Encode(pull)
	}))
	defer server.Close()
	client := testClient(t, server, engine, f.verifier)
	_, err := client.Pull(context.Background())
	check(t, err)
	if calls.Load() != 2 || engine.State().Cloud.Environments["env"].Values["TOKEN"] != "old-env-data" {
		t.Fatal("new authorized environment history was missed")
	}
}
func fmtInt(value int64) string { return strconv.FormatInt(value, 10) }

func TestTLSVerificationAndIdentityCannotBeWeakened(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true
	if _, err := New(Config{Endpoint: server.URL, HTTPClient: &http.Client{Transport: transport}, AccountID: "acct", AccountGeneration: 1, DeviceID: "dev", Token: "synthetic", Engine: testEngine(t), Verifier: acceptVerifier{}}); err == nil {
		t.Fatal("TLS verification disabled")
	}
	if _, err := New(Config{Endpoint: server.URL, AccountID: "acct/other", AccountGeneration: 1, DeviceID: "dev", Token: "synthetic", Engine: testEngine(t), Verifier: acceptVerifier{}}); err == nil {
		t.Fatal("invalid identity accepted")
	}
}
