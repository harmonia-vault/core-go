package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFreshServerReadyMetadataStrict(t *testing.T) {
	if port, err := readyPort([]byte(`{"port":43210,"mailboxPath":"/test/emails"}`)); err != nil || port != 43210 {
		t.Fatal("strict fresh ready rejected")
	}
	for _, body := range []string{`{"endpoint":"http://127.0.0.1:43210"}`, `{"port":80,"mailboxPath":"/test/emails"}`, `{"port":43210,"mailboxPath":null}`, `{"port":43210,"mailboxPath":"/test/emails","accountId":"seeded"}`, `{"port":43210,"mailboxPath":"/test/emails"} {}`} {
		if _, err := readyPort([]byte(body)); err == nil {
			t.Fatal("nonempty/unknown ready accepted")
		}
	}
}
func TestEmptyInstanceRequiresExactRegistrationPolicy(t *testing.T) {
	valid := `{"product":"harmonia","status":"experimental","protocol":{"supportedMajors":[1],"capabilities":["registration-policy-v1","email-proof-v1"]},"initialRegistrationAvailable":true,"allowRegistration":false,"emailVerificationRequired":true}`
	if verifyEmptyInstance([]byte(valid)) != nil {
		t.Fatal("fixed empty metadata rejected")
	}
	for _, body := range []string{`{"ok":true}`, strings.Replace(valid, `"harmonia"`, `"other"`, 1), strings.Replace(valid, `"supportedMajors":[1]`, `"supportedMajors":[2]`, 1), strings.Replace(valid, `"initialRegistrationAvailable":true`, `"initialRegistrationAvailable":false`, 1), strings.Replace(valid, `"emailVerificationRequired":true`, `"emailVerificationRequired":false`, 1), strings.Replace(valid, `"allowRegistration":false`, `"allowRegistration":true`, 1), strings.Replace(valid, `"status":"experimental",`, `"status":"experimental","accountCount":0,`, 1)} {
		if verifyEmptyInstance([]byte(body)) == nil {
			t.Fatal("arbitrary 200 or seeded-policy metadata accepted")
		}
	}
}
func TestEphemeralChainStandardVerificationAndPublicOnlyOutput(t *testing.T) {
	now := time.Now()
	chain, caPEM, err := ephemeralTLS(now)
	if err != nil {
		t.Fatal("ephemeral TLS generation failed")
	}
	if len(chain.Certificate) != 2 || chain.PrivateKey == nil || bytes.Contains(caPEM, []byte("PRIVATE"+" KEY")) {
		t.Fatal("nonpublic output shape")
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("not exactly one public certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA || !bytes.Equal(ca.SubjectKeyId, ca.AuthorityKeyId) {
		t.Fatal("CA binding invalid")
	}
	leaf, err := x509.ParseCertificate(chain.Certificate[0])
	if err != nil || !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) {
		t.Fatal("leaf CA binding invalid")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, host := range []string{"10.0.2.2", "127.0.0.1", "localhost", "::1"} {
		if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, CurrentTime: now}); err != nil {
			t.Fatal("standard local hostname verification failed")
		}
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example.invalid", CurrentTime: now}); err == nil {
		t.Fatal("hostname bypass accepted")
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "10.0.2.2", CurrentTime: now.Add(25 * time.Hour)}); err == nil {
		t.Fatal("expired chain accepted")
	}
}
func TestFixedCountersAndLostResponseTrackAcceptedSeparately(t *testing.T) {
	var c counters
	var lose atomic.Value
	lose.Store("environment")
	response := func(status int) *http.Response {
		u, _ := url.Parse("http://127.0.0.1/v1/accounts/synthetic/environment-changes-v4")
		return &http.Response{StatusCode: status, Request: &http.Request{Method: "POST", URL: u}, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}
	}
	rejected := response(403)
	if c.response(rejected, &lose) != nil {
		t.Fatal("counter update failed")
	}
	_ = rejected.Body.Close()
	if c.EnvironmentAttempt.Load() != 1 || c.EnvironmentAccepted.Load() != 0 || lose.Load() != "environment" {
		t.Fatal("rejection consumed accepted-response fault")
	}
	accepted := response(200)
	if c.response(accepted, &lose) != nil {
		t.Fatal("counter update failed")
	}
	body, _ := io.ReadAll(accepted.Body)
	_ = accepted.Body.Close()
	if accepted.StatusCode != 502 || string(body) != `{"error":"synthetic_lost_response"}` || c.EnvironmentAttempt.Load() != 2 || c.EnvironmentAccepted.Load() != 1 || lose.Load() != "" {
		t.Fatal("accepted response fault accounting invalid")
	}
	public := c.public()
	encoded, err := json.Marshal(public)
	if err != nil || len(public) != 16 || bytes.Contains(encoded, []byte("token")) || bytes.Contains(encoded, []byte("accountId")) {
		t.Fatal("counter leaked nonpublic data")
	}
}
func TestProjectionNoNetworkAndStrictControls(t *testing.T) {
	var c counters
	var lose atomic.Value
	lose.Store("")
	handler := testProjection(&c, &lose, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	for _, item := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/test/counters", "", 200}, {"POST", "/test/counters", "", 400}, {"GET", "/test/counters?extra=1", "", 400},
		{"POST", "/test/control", `{"lose":"mutation"}`, 200}, {"POST", "/test/control", `{"lose":"environment"}`, 200}, {"POST", "/test/control", `{"lose":"approvalV5"}`, 200},
		{"GET", "/test/control", "", 400}, {"POST", "/test/control", `{"lose":"register"}`, 400}, {"POST", "/test/control", `{"lose":"mutation","token":"synthetic-rejected"}`, 400}, {"POST", "/test/control", `{"lose":"mutation"} {}`, 400},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(item.method, item.path, strings.NewReader(item.body)))
		if rec.Code != item.status || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("fixed projection shape rejected incorrectly")
		}
	}
}
