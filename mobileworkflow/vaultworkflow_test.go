package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	_, sign, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	_, receive, e := cryptox.GenerateReceivingKey()
	if e != nil {
		t.Fatal(e)
	}
	return Config{Endpoint: "https://synthetic.example.invalid", SigningKey: sign, ReceivingPrivateKey: receive, SaveProtectedState: func([]byte) error { return nil }}
}
func TestNativeWorkflowRejectsUnsafeEndpointTLSAndMissingEncryptedOwner(t *testing.T) {
	for _, endpoint := range []string{"http://synthetic.example.invalid", "https://name:password@synthetic.example.invalid", "https://synthetic.example.invalid?token=value", "https://synthetic.example.invalid#secret"} {
		c := testConfig(t)
		c.Endpoint = endpoint
		if w, e := New(c); e == nil {
			w.Close()
			t.Fatalf("unsafe endpoint accepted: %q", endpoint)
		}
	}
	c := testConfig(t)
	c.SaveProtectedState = nil
	if _, e := New(c); e == nil {
		t.Fatal("no native encrypted state owner accepted")
	}
	c = testConfig(t)
	c.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, e := New(c); e == nil {
		t.Fatal("TLS verification disabled")
	}
}
func TestProtectedContextBindsNativeDeviceEndpointAndSyntheticFlag(t *testing.T) {
	c := testConfig(t)
	w, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	blob, e := w.ExportProtectedState()
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	other := testConfig(t)
	other.ProtectedState = blob
	if _, e := New(other); e == nil {
		t.Fatal("another device consumed native context")
	}
	c.ProtectedState = blob
	c.Endpoint = "https://another.example.invalid"
	if _, e := New(c); e == nil {
		t.Fatal("another endpoint consumed native context")
	}
	c.Endpoint = "https://synthetic.example.invalid"
	var state protectedState
	if json.Unmarshal(blob, &state) != nil {
		t.Fatal("context decode")
	}
	state.Cloud.Synthetic = true
	c.ProtectedState, _ = json.Marshal(state)
	if _, e := New(c); e == nil {
		t.Fatal("synthetic fixture flag accepted for workflow")
	}
	if bytes.Contains(blob, c.SigningKey.Seed()) || bytes.Contains(blob, c.ReceivingPrivateKey) {
		t.Fatal("device private material leaked to protected context")
	}
}
func TestUntrustedAndClosedWorkflowCannotReadSignOrApprove(t *testing.T) {
	c := testConfig(t)
	w, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.View(); !errors.Is(e, ErrNotTrusted) {
		t.Fatal("untrusted view succeeded", e)
	}
	if e = w.ApproveDevice(context.Background(), "12345678"); !errors.Is(e, ErrUnsupported) {
		t.Fatal("unconnected PAKE approved")
	}
	if e = w.Recover(context.Background(), "not-real-code"); !errors.Is(e, ErrUnsupported) {
		t.Fatal("unconnected recovery succeeded")
	}
	w.Close()
	if _, e = w.View(); !errors.Is(e, ErrClosed) {
		t.Fatal("closed view returned secrets")
	}
	if _, e = w.ExportProtectedState(); !errors.Is(e, ErrClosed) {
		t.Fatal("closed context export succeeded")
	}
}

func TestProtectedContextRejectsDuplicateFieldsAndUnconfirmedCache(t *testing.T) {
	c := testConfig(t)
	w, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	blob, e := w.ExportProtectedState()
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	c.ProtectedState = append([]byte(`{"version":2,`), blob[1:]...)
	if _, e = New(c); e == nil {
		t.Fatal("duplicate field context accepted")
	}
	var state protectedState
	if json.Unmarshal(blob, &state) != nil {
		t.Fatal("decode")
	}
	state.AccountID = "acct"
	state.AccountGeneration = "1"
	state.Cloud.Cloud.AccountID = "acct"
	state.Cloud.Cloud.AccountGeneration = 1
	c.ProtectedState, _ = json.Marshal(state)
	if _, e = New(c); e == nil {
		t.Fatal("unconfirmed cloud account accepted")
	}
	for _, body := range []string{`{"x":{"a":1,"a":2}}`, `{"x":[{"a":1,"a":2}]}`, `{"x":1} {"x":2}`} {
		var out map[string]any
		if decode([]byte(body), &out) == nil {
			t.Fatal("ambiguous JSON accepted", body)
		}
	}
}

func TestNativeWorkflowInspectsAndClonesDefaultHTTPTransport(t *testing.T) {
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	if _, err := New(testConfig(t)); err == nil {
		t.Fatal("unsafe default transport bypassed verification")
	}
	c := testConfig(t)
	provided := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	c.HTTPClient = &http.Client{Transport: provided}
	w, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	cloned, ok := w.http.Transport.(*http.Transport)
	if !ok || cloned == provided || cloned.TLSClientConfig == provided.TLSClientConfig {
		t.Fatal("TLS transport state was not isolated")
	}
}

func TestNativeLogoutPersistsClosedAccountAndClearsKeys(t *testing.T) {
	c := testConfig(t)
	var persisted []byte
	c.SaveProtectedState = func(value []byte) error { persisted = bytes.Clone(value); return nil }
	w, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = w.Logout(); e != nil {
		t.Fatal(e)
	}
	if len(w.signing) != 0 || len(w.receiving) != 0 {
		t.Fatal("logout retained process key material")
	}
	if _, e = w.View(); !errors.Is(e, ErrClosed) {
		t.Fatal("logged out workflow remained readable", e)
	}
	var state protectedState
	if json.Unmarshal(persisted, &state) != nil || !state.Cloud.AccountClosed || state.Root != nil || state.Pending != nil {
		t.Fatal("logout did not persist closed account")
	}
	c.ProtectedState = persisted
	other, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = other.Login(context.Background(), "synthetic@example.invalid", "synthetic-only"); e == nil {
		t.Fatal("login revived closed context")
	}
}
