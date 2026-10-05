package syncclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/pairing"
)

func TestLoginReturnsRandomSessionWithoutDeviceTrust(t *testing.T) {
	credential := cryptox.PasswordCredential("synthetic-password-only")
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		calls.Add(1)
		if r.URL.Path != "/v1/login" || r.Header.Get("Authorization") != "" || r.Header.Get("Cache-Control") != "no-store" {
			t.Error("login request had wrong routing/authorization/cache policy")
		}
		var input struct {
			Email      string `json:"email"`
			Credential string `json:"credential"`
		}
		_ = json.NewDecoder(r.Body).Decode(&input)
		if input.Email != "synthetic@example.invalid" || input.Credential != fmtHex(credential[:]) {
			t.Error("login derivation changed")
		}
		_ = json.NewEncoder(w).Encode(LoginResult{AccountID: "acct", AccountGeneration: "1", Token: cryptox.EncodeBase64(make([]byte, 32)), ExpiresAt: time.Now().Add(time.Hour).Unix()})
	}))
	defer server.Close()
	result, err := Login(context.Background(), LoginConfig{Endpoint: server.URL, HTTPClient: server.Client(), Email: "synthetic@example.invalid", Credential: fmtHex(credential[:])})
	check(t, err)
	if result.AccountID != "acct" || calls.Load() != 1 {
		t.Fatal(result)
	}
	if _, err := Login(context.Background(), LoginConfig{Endpoint: "http://synthetic.invalid", Email: "synthetic@example.invalid", Credential: fmtHex(credential[:])}); err == nil {
		t.Fatal("insecure login accepted")
	}
}
func fmtHex(data []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, 2*len(data))
	for i, b := range data {
		out[2*i] = alphabet[b>>4]
		out[2*i+1] = alphabet[b&15]
	}
	return string(out)
}
func TestDefaultEnrollmentCannotReachServerOrAcceptUnsignedReceipt(t *testing.T) {
	f := newCryptoFixture(t)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		calls.Add(1)
		http.Error(w, "synthetic unexpected request", 500)
	}))
	defer server.Close()
	config := EnrollmentConfig{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: "acct", AccountGeneration: 1, DeviceID: "dev", LoginToken: cryptox.EncodeBase64(make([]byte, 32)), SigningKey: f.devicePrivate, ReceivingPrivateKey: f.receivingPrivate, Engine: testEngine(t)}
	e, err := NewEnrollmentV5(config)
	check(t, err)
	defer e.Close()
	if !pairing.NativeAvailable() {
		if _, err = e.Begin(context.Background(), "manager", "pair-1", []byte("12345678")); !errors.Is(err, pairing.ErrUnavailable) || calls.Load() != 0 {
			t.Fatal("default build sent enrollment request", err)
		}
	}
	if _, err = ResumeEnrollmentV5(config, EnrollmentReceiptV5{IdempotencyKey: "pair-1"}); err == nil || calls.Load() != 0 {
		t.Fatal("unsigned receipt resumed")
	}
	if _, err = e.Receipt(); err == nil {
		t.Fatal("receipt before PAKE confirmation")
	}
}
func TestLoginErrorsNeverEchoCredentialAndRedirectNeverForwards(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		forwarded.Add(1)
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		w.Header().Set("Location", target.URL)
		w.WriteHeader(307)
		_, _ = w.Write([]byte("SYNTHETIC_SECRET"))
	}))
	defer source.Close()
	_, err := Login(context.Background(), LoginConfig{Endpoint: source.URL, HTTPClient: source.Client(), Email: "synthetic@example.invalid", Credential: strings.Repeat("a", 64)})
	if err == nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET") || forwarded.Load() != 0 {
		t.Fatal(err)
	}
}
