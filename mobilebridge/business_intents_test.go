package mobilebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
)

func TestAccountLoginIntentUsesVerifiedHTTPSAndNeverTrustsDevice(t *testing.T) {
	password := "synthetic-account-password"
	hash := sha256.Sum256([]byte(password))
	credential := hex.EncodeToString(hash[:])
	var calls atomic.Uint64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct {
			Email      string `json:"email"`
			Credential string `json:"credential"`
		}
		if r.Method != "POST" || r.URL.Path != "/v1/login" || r.Header.Get("Cache-Control") != "no-store" || json.NewDecoder(r.Body).Decode(&request) != nil || request.Email != "synthetic@fixture.invalid" || request.Credential != credential {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"accountId": "synthetic-account", "accountGeneration": "1", "token": cryptox.EncodeBase64(bytes.Repeat([]byte{71}, 32)), "expiresAt": time.Now().Unix() + 300})
	}))
	defer server.Close()
	device, err := NewDevice()
	if err != nil {
		t.Fatal("synthetic device creation failed")
	}
	defer device.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	store := &memorySealed{}
	flow, err := device.OpenWorkflow(server.URL, "synthetic-login-native/slot/v1", nil, ca, store)
	if err != nil {
		t.Fatal("explicit valid test CA rejected")
	}
	defer flow.Close()
	data, err := flow.executeBusinessIntent(context.Background(), workflowCommand{operation: "loginAccount", fields: map[string]string{"email": "synthetic@fixture.invalid", "password": password}})
	if err != nil || calls.Load() != 1 {
		t.Fatal("mature HTTPS login failed")
	}
	encoded, err := json.Marshal(data)
	if err != nil || string(encoded) != `{"authenticated":true,"trustedDevice":false}` || len(store.packet) != 0 {
		t.Fatal("login leaked state or became trusted")
	}
	if data, err := flow.executeBusinessIntent(context.Background(), workflowCommand{operation: "restoreSession", fields: map[string]string{}}); data != nil || !errors.Is(err, mobileworkflow.ErrNotTrusted) {
		t.Fatal("login restored a trusted session")
	}
	if _, err := flow.workflow.View(); !errors.Is(err, mobileworkflow.ErrNotTrusted) {
		t.Fatal("login unlocked vault view")
	}
	if data, err := flow.executeBusinessIntent(context.Background(), workflowCommand{operation: "loginAccount", fields: map[string]string{"email": "synthetic@fixture.invalid", "password": "synthetic-wrong-password"}}); err == nil || data != nil {
		t.Fatal("rejected login returned success")
	}
	flow.Close()
	if flow.workflow != nil || len(flow.key) != 0 {
		t.Fatal("per-operation workflow survived close")
	}
	untrusted, err := device.OpenWorkflow(server.URL, "synthetic-login-native/slot/v1", nil, nil, store)
	if err != nil {
		t.Fatal("new untrusted TLS context rejected before request")
	}
	defer untrusted.Close()
	before := calls.Load()
	if data, err := untrusted.executeBusinessIntent(context.Background(), workflowCommand{operation: "loginAccount", fields: map[string]string{"email": "synthetic@fixture.invalid", "password": password}}); err == nil || data != nil || calls.Load() != before {
		t.Fatal("unknown CA login was accepted")
	}
}

func TestAccountAndOriginalBusinessIntentStrictSurface(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"operation":"loginAccount","endpoint":"https://vault.example.invalid","email":"synthetic@fixture.invalid","password":"synthetic-only"}`,
		`{"version":1,"operation":"businessPendingInfo","endpoint":"https://vault.example.invalid"}`,
		`{"version":1,"operation":"restoreSession","endpoint":"https://vault.example.invalid"}`,
		`{"version":1,"operation":"retryBusinessOperation","endpoint":"https://vault.example.invalid","id":"original-operation"}`,
	} {
		if _, err := parseWorkflowCommand(raw); err != nil {
			t.Fatal("explicit business intent rejected")
		}
	}
	for _, raw := range []string{
		`{"version":1,"operation":"loginAccount","endpoint":"https://vault.example.invalid","email":"synthetic@fixture.invalid","password":"synthetic-only","trustedDevice":"true"}`,
		`{"version":1,"operation":"loginAccount","endpoint":"https://vault.example.invalid","email":"synthetic@fixture.invalid","password":"synthetic-only","token":"injected"}`,
		`{"version":1,"operation":"businessPendingInfo","endpoint":"https://vault.example.invalid","id":"replacement"}`,
		`{"version":1,"operation":"restoreSession","endpoint":"https://vault.example.invalid","accountId":"untrusted-header"}`,
		`{"version":1,"operation":"restoreSession","endpoint":"https://vault.example.invalid","trustedDevice":"true"}`,
		`{"version":1,"operation":"retryBusinessOperation","endpoint":"https://vault.example.invalid","id":"original-operation","value":"replacement"}`,
		`{"version":1,"operation":"retryBusinessOperation","endpoint":"https://vault.example.invalid","id":"original-operation","environmentId":"replacement"}`,
		`{"version":1,"operation":"retryBusinessOperation","endpoint":"https://other.example.invalid?token=forbidden","id":"original-operation"}`,
	} {
		if _, err := parseWorkflowCommand(raw); err == nil {
			t.Fatal("injected business intent accepted")
		}
	}
	encoded, err := WorkflowProfile()
	var profile struct {
		RealVaultReady bool     `json:"realVaultReady"`
		Operations     []string `json:"operations"`
	}
	if err != nil || json.Unmarshal([]byte(encoded), &profile) != nil || profile.RealVaultReady {
		t.Fatal("business profile opened overall trust")
	}
	for name := range businessIntentFields {
		found := false
		for _, op := range profile.Operations {
			if op == name {
				found = true
			}
		}
		if !found {
			t.Fatal("explicit business capability absent")
		}
	}
}
