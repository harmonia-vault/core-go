package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const discoveryTestAccount = "synthetic-account"
const discoveryTestDevice = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const discoveryTestEnvironment = "synthetic-initial-env"
const discoveryTestComplete = "/v1/accounts/synthetic-account/vault-initializations/synthetic-init/complete"
const discoveryTestPull = "/v1/accounts/synthetic-account/pull"

func discoveryTestBytes(size int, fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, size))
}
func discoveryInitBody(state string) map[string]any {
	nonce := discoveryTestBytes(32, 0)
	hash := strings.Repeat("b", 64)
	return map[string]any{"state": state, "challengeId": "synthetic-challenge", "idempotencyKey": "synthetic-init", "nonce": nonce, "expiresAt": 2000000000,
		"proposalHash": hash, "signingPayload": []string{"harmonia/vault-initialize/v1", discoveryTestAccount, "1", strings.Repeat("c", 64), "synthetic-challenge", nonce, "2000000000", hash}, "sequence": 1, "replayed": false}
}
func discoveryPullBody() map[string]any {
	return map[string]any{"accountId": discoveryTestAccount, "accountGeneration": "1", "sequence": 1,
		"grants": []any{map[string]any{"grant": map[string]any{"accountId": discoveryTestAccount, "accountGeneration": "1", "issuerDeviceId": discoveryTestDevice, "subjectDeviceId": discoveryTestDevice,
			"subjectSigningPublicKey": discoveryTestBytes(32, 1), "subjectReceivingPublicKey": discoveryTestBytes(32, 2), "environmentId": discoveryTestEnvironment,
			"keyVersion": "1", "grantGeneration": "1", "role": "admin", "expiresAt": "0", "idempotencyKey": "synthetic-initial-grant", "envelope": discoveryTestBytes(80, 3)}, "signature": discoveryTestBytes(64, 4)}},
		"events": []any{}, "environmentEvents": []any{}, "issuerEvidence": map[string]any{"syntheticShapeOnly": true}}
}
func discoveryJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic("synthetic JSON encoding failed")
	}
	return data
}
func discoveryPrepared(t *testing.T) *publicDiscovery {
	t.Helper()
	d := &publicDiscovery{}
	if !d.observe("POST", discoveryTestComplete, 200, discoveryJSON(discoveryInitBody("complete"))) {
		t.Fatal("fixed complete metadata rejected")
	}
	return d
}
func TestPublicDiscoveryOnlyAcceptedInitializationAndFirstExactPull(t *testing.T) {
	d := discoveryPrepared(t)
	if _, ok := d.snapshot(); ok {
		t.Fatal("initialization alone exposed discovery")
	}
	if !d.observe("GET", discoveryTestPull, 200, discoveryJSON(discoveryPullBody())) {
		t.Fatal("strict first pull discovery rejected")
	}
	result, ok := d.snapshot()
	if !ok || result.AccountGeneration != "1" || result.ManagerDeviceID != discoveryTestDevice || result.EnvironmentID != discoveryTestEnvironment {
		t.Fatal("public scope projection invalid")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(discoveryJSON(result), &fields)
	if len(fields) != 3 || fields["accountGeneration"] == nil || fields["managerDeviceId"] == nil || fields["environmentId"] == nil {
		t.Fatal("projection includes nonpublic fields")
	}
	different := discoveryPullBody()
	different["accountGeneration"] = "2"
	if d.observe("GET", discoveryTestPull, 200, discoveryJSON(different)) {
		t.Fatal("second pull replaced frozen discovery")
	}
	second, ok := d.snapshot()
	if !ok || second != result {
		t.Fatal("second pull mutated original discovery")
	}
	other := discoveryInitBody("complete")
	other["signingPayload"].([]string)[2] = "2"
	if d.observe("POST", discoveryTestComplete, 200, discoveryJSON(other)) {
		t.Fatal("second completion replaced frozen discovery")
	}
}
func TestPublicDiscoveryRejectsUnboundSources(t *testing.T) {
	cases := []struct {
		name   string
		alter  func(map[string]any)
		path   string
		status int
		noInit bool
	}{
		{name: "cross-account-path", path: "/v1/accounts/other-account/pull"},
		{name: "cross-account-body", alter: func(v map[string]any) { v["accountId"] = "other-account" }},
		{name: "cross-generation", alter: func(v map[string]any) { v["accountGeneration"] = "2" }},
		{name: "cross-sequence", alter: func(v map[string]any) { v["sequence"] = 2 }},
		{name: "multiple-grants", alter: func(v map[string]any) { g := v["grants"].([]any); v["grants"] = append(g, g[0]) }},
		{name: "non-self", alter: func(v map[string]any) {
			v["grants"].([]any)[0].(map[string]any)["grant"].(map[string]any)["issuerDeviceId"] = strings.Repeat("d", 64)
		}},
		{name: "non-admin", alter: func(v map[string]any) {
			v["grants"].([]any)[0].(map[string]any)["grant"].(map[string]any)["role"] = "rw"
		}},
		{name: "non-kv1", alter: func(v map[string]any) {
			v["grants"].([]any)[0].(map[string]any)["grant"].(map[string]any)["keyVersion"] = "2"
		}},
		{name: "uncompleted", noInit: true},
		{name: "non-200", status: 403},
		{name: "malformed-device-id", alter: func(v map[string]any) {
			g := v["grants"].([]any)[0].(map[string]any)["grant"].(map[string]any)
			g["subjectDeviceId"] = "invalid-id"
			g["issuerDeviceId"] = "invalid-id"
		}},
		{name: "extra-field", alter: func(v map[string]any) { v["trustedDevice"] = true }},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			var d *publicDiscovery
			if item.noInit {
				d = &publicDiscovery{}
			} else {
				d = discoveryPrepared(t)
			}
			value := discoveryPullBody()
			if item.alter != nil {
				item.alter(value)
			}
			path := item.path
			if path == "" {
				path = discoveryTestPull
			}
			status := item.status
			if status == 0 {
				status = 200
			}
			if d.observe("GET", path, status, discoveryJSON(value)) {
				t.Fatal("unbound public source accepted")
			}
			if _, ok := d.snapshot(); ok {
				t.Fatal("rejected source exposed public scope")
			}
		})
	}
	for _, state := range []string{"pending", "complete"} {
		d := &publicDiscovery{}
		value := discoveryInitBody(state)
		if state == "complete" {
			value["replayed"] = true
		}
		if d.observe("POST", discoveryTestComplete, 200, discoveryJSON(value)) {
			t.Fatal("unaccepted initialization projected")
		}
	}
}
func TestPublicDiscoveryPreservesExactResponseStreamAndClearsBuffer(t *testing.T) {
	d := &publicDiscovery{}
	u, _ := url.Parse("http://127.0.0.1" + discoveryTestComplete)
	data := discoveryJSON(discoveryInitBody("complete"))
	response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, ContentLength: int64(len(data)),
		Request: &http.Request{Method: "POST", URL: u}, Body: io.NopCloser(bytes.NewReader(data))}
	d.response(response)
	wrapper, ok := response.Body.(*discoveryBody)
	if !ok {
		t.Fatal("observer not attached")
	}
	actual, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(actual, data) || response.StatusCode != 200 || response.ContentLength != int64(len(data)) || response.Header.Get("Content-Type") != "application/json" {
		t.Fatal("observer rewrote accepted response")
	}
	if wrapper.data != nil || !wrapper.observed || !d.haveInitialization {
		t.Fatal("observer retained raw response")
	}
	_ = response.Body.Close()
	d.response(&http.Response{StatusCode: 200, Request: &http.Request{Method: "POST", URL: u}, Body: io.NopCloser(strings.NewReader("{}"))})
	if !d.haveInitialization || d.account != discoveryTestAccount {
		t.Fatal("second response replaced initialization")
	}
	incomplete := &publicDiscovery{}
	bad := &http.Response{StatusCode: 200, Request: &http.Request{Method: "POST", URL: u}, Body: io.NopCloser(bytes.NewReader(data))}
	incomplete.response(bad)
	buffer := make([]byte, 8)
	_, _ = bad.Body.Read(buffer)
	_ = bad.Body.Close()
	if !incomplete.blocked || incomplete.haveInitialization {
		t.Fatal("partial response allowed discovery")
	}
	oversized := &publicDiscovery{}
	big := &http.Response{StatusCode: 200, Request: &http.Request{Method: "POST", URL: u}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 1048577)))}
	oversized.response(big)
	_, _ = io.Copy(io.Discard, big.Body)
	_ = big.Body.Close()
	if !oversized.blocked || oversized.haveInitialization {
		t.Fatal("overflow response allowed discovery")
	}
}
func TestPublicDiscoveryEndpointStrictAndUnavailableClosed(t *testing.T) {
	d := &publicDiscovery{}
	handler := withDiscovery(d, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	for _, item := range []struct {
		method, path string
		status       int
	}{{"GET", "/test/discovery", 409}, {"POST", "/test/discovery", 400}, {"GET", "/test/discovery?query=1", 400}, {"GET", "/test/discovery?", 400}} {
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, httptest.NewRequest(item.method, item.path, nil))
		if result.Code != item.status || result.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("discovery endpoint not closed/strict")
		}
	}
	d = discoveryPrepared(t)
	d.observe("GET", discoveryTestPull, 200, discoveryJSON(discoveryPullBody()))
	result := httptest.NewRecorder()
	withDiscovery(d, handler).ServeHTTP(result, httptest.NewRequest("GET", "/test/discovery", nil))
	if result.Code != 200 || !bytes.Equal(bytes.TrimSpace(result.Body.Bytes()), discoveryJSON(publicScope{"1", discoveryTestDevice, discoveryTestEnvironment})) {
		t.Fatal("public discovery wire incorrect")
	}
}
