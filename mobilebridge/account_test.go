package mobilebridge

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func accountTestCommand(t *testing.T, endpoint, operation string) string {
	t.Helper()
	command := map[string]any{"version": 1, "endpoint": endpoint, "operation": operation}
	switch operation {
	case "register", "loginAccount":
		command["email"], command["password"] = "synthetic@example.invalid", "synthetic-password"
	case "requestVerificationEmail":
		command["email"] = "synthetic@example.invalid"
	case "verifyEmail":
		command["accountId"], command["accountGeneration"], command["code"] = "synthetic-account", "1", "A2BC3DE4"
	}
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func checkAccountFailure(t *testing.T, endpoint string, ca []byte, operation, want string) {
	t.Helper()
	command := accountTestCommand(t, endpoint, operation)
	for _, protected := range []bool{false, true} {
		var raw string
		var err error
		if protected {
			device, e := NewDevice()
			if e != nil {
				t.Fatal(e)
			}
			defer device.Close()
			workflow, e := device.OpenWorkflow(endpoint, "synthetic-account-errors", nil, ca, &memorySealed{})
			if e != nil {
				t.Fatal(e)
			}
			defer workflow.Close()
			raw, err = workflow.Execute(command)
		} else {
			raw, err = ExecuteAccount(command, ca)
		}
		if err != nil {
			t.Fatal(err)
		}
		var reply map[string]any
		if json.Unmarshal([]byte(raw), &reply) != nil || len(reply) != 4 || reply["version"] != float64(1) || reply["experimental"] != true || reply["ok"] != false || reply["code"] != want {
			t.Fatalf("protected=%t: want %s without server text or success data, got %s", protected, want, raw)
		}
	}
}

func TestAccountFailuresReachNativeBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, operation string
		status          int
		body, want      string
	}{
		{"existing-account", "register", 409, `{"error":"account_exists"}`, "ACCOUNT_EXISTS"},
		{"old-account-register", "register", 409, `{"error":"account_format_unsupported"}`, "ACCOUNT_FORMAT_UNSUPPORTED"},
		{"old-account-login", "loginAccount", 409, `{"error":"account_format_unsupported"}`, "ACCOUNT_FORMAT_UNSUPPORTED"},
		{"registration-closed", "register", 403, `{"error":"registration_disabled"}`, "REGISTRATION_DISABLED"},
		{"invalid-email", "register", 400, `{"error":"email_invalid"}`, "EMAIL_INVALID"},
		{"mail-not-configured", "register", 503, `{"error":"email_verification_unavailable"}`, "EMAIL_UNAVAILABLE"},
		{"delivery-failed", "register", 503, `{"error":"email_delivery_failed"}`, "EMAIL_DELIVERY_FAILED"},
		{"resend-failed", "requestVerificationEmail", 503, `{"error":"email_delivery_failed"}`, "EMAIL_DELIVERY_FAILED"},
		{"login-rejected", "loginAccount", 401, `{"error":"unauthorized"}`, "LOGIN_FAILED"},
		{"non-login-rejected", "verifyEmail", 401, `{"error":"unauthorized"}`, "ACCOUNT_REQUEST_FAILED"},
		{"proof-required", "loginAccount", 403, `{"error":"email_verification_required"}`, "EMAIL_VERIFICATION_REQUIRED"},
		{"account-changed", "verifyEmail", 409, `{"error":"account_changed"}`, "ACCOUNT_CHANGED"},
		{"generation-changed", "verifyEmail", 401, `{"error":"generation_stale"}`, "ACCOUNT_CHANGED"},
		{"expired", "verifyEmail", 401, `{"error":"registration_expired"}`, "REGISTRATION_EXPIRED"},
		{"invalid-code", "verifyEmail", 401, `{"error":"email_code_invalid"}`, "EMAIL_CODE_INVALID"},
		{"old-code", "verifyEmail", 401, `{"error":"email_code_expired"}`, "EMAIL_CODE_EXPIRED"},
		{"exhausted-code", "verifyEmail", 429, `{"error":"email_code_attempts_exhausted"}`, "EMAIL_CODE_EXHAUSTED"},
		{"unsupported-protocol", "register", 426, `{"error":"protocol_major_unsupported"}`, "SERVER_RESPONSE_INVALID"},
		{"server-failed", "register", 500, `{"error":"internal_error"}`, "SERVER_UNAVAILABLE"},
		{"limited-without-delay", "register", 429, `{"error":"email_request_limited"}`, "REQUEST_RATE_LIMITED"},
		{"untrusted-code", "register", 400, `{"error":"synthetic-password"}`, "ACCOUNT_REQUEST_FAILED"},
		{"untrusted-fields", "register", 409, `{"error":"account_exists","message":"synthetic-password"}`, "ACCOUNT_REQUEST_FAILED"},
		{"untrusted-login-fields", "loginAccount", 401, `{"error":"unauthorized","message":"synthetic-password"}`, "ACCOUNT_REQUEST_FAILED"},
		{"invalid-register-response", "register", 200, `not-json-synthetic-password`, "SERVER_RESPONSE_INVALID"},
		{"invalid-login-response", "loginAccount", 200, `{"accountId":"synthetic-account"}`, "SERVER_RESPONSE_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Harmonia-Protocol-Major", "2")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			checkAccountFailure(t, server.URL, ca, tc.operation, tc.want)
		})
	}
}

func TestAccountConnectionAndProtocolFailures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error":"synthetic-password"}`))
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	for _, operation := range []string{"register", "loginAccount"} {
		checkAccountFailure(t, server.URL, ca, operation, "SERVER_RESPONSE_INVALID")
	}
	server.Close()
	for _, operation := range []string{"register", "loginAccount"} {
		checkAccountFailure(t, server.URL, ca, operation, "NETWORK_ERROR")
	}
}
