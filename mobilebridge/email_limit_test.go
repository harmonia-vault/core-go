package mobilebridge

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmailResendHTTPSAndNativeCooldownReply(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		seconds float64
	}{
		{"expired", 401, `{"error":"registration_expired"}`, 0},
		{"accepted", 200, `{"accepted":true}`, 0},
		{"cooldown", 429, `{"error":"email_request_limited","retryAfterSeconds":17}`, 17},
		{"ban", 429, `{"error":"email_ip_blocked","retryAfterSeconds":899}`, 899},
		{"missing-delay", 429, `{"error":"email_request_limited"}`, 0},
		{"unbounded", 429, `{"error":"email_ip_blocked","retryAfterSeconds":999999999}`, 0},
		{"injected", 429, `{"error":"email_request_limited","retryAfterSeconds":17,"secret":"synthetic"}`, 0},
		{"duplicate", 429, `{"error":"email_request_limited","retryAfterSeconds":17,"retryAfterSeconds":18}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Harmonia-Protocol-Major", "2")

				if r.Method != "POST" || r.URL.Path != "/v1/email-verification/request" || r.Header.Get("Authorization") != "" {
					t.Error("重发请求路径或认证边界错误")
				}
				var input map[string]string
				if json.NewDecoder(r.Body).Decode(&input) != nil || len(input) != 1 || input["email"] != "synthetic@example.invalid" {
					t.Error("重发接口只能接收目标邮箱")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			command, _ := json.Marshal(map[string]any{"version": 1, "operation": "requestVerificationEmail", "endpoint": server.URL, "email": "synthetic@example.invalid"})
			raw, err := ExecuteAccount(string(command), ca)
			if err != nil {
				t.Fatal(err)
			}
			var reply map[string]any
			if json.Unmarshal([]byte(raw), &reply) != nil {
				t.Fatal("无效桥接响应")
			}
			if tc.status == 200 {
				if reply["ok"] != true || reply["data"].(map[string]any)["accepted"] != true {
					t.Fatal(raw)
				}
			} else if tc.name == "expired" {
				if reply["ok"] != false || reply["code"] != "REGISTRATION_EXPIRED" || reply["data"] != nil {
					t.Fatal("过期注册未映射为重新注册错误", raw)
				}
			} else if tc.seconds > 0 {
				if reply["ok"] != false || reply["code"] != "EMAIL_RATE_LIMITED" || reply["retryAfterSeconds"] != tc.seconds {
					t.Fatal(raw)
				}
			} else if reply["ok"] != false || reply["code"] == "EMAIL_RATE_LIMITED" || reply["retryAfterSeconds"] != nil {
				t.Fatal("不可信错误字段被当作冷却采用")
			}
		})
	}
}

func TestAccountResetMailHTTPSReturnsCooldownWithoutAcceptingOrTrusting(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		if r.URL.Path != "/v1/account-reset/request" {
			t.Error("错误重置邮件路径")
		}
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":"email_ip_blocked","retryAfterSeconds":900}`))
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	owner, err := OpenNativeAccountResetMail(server.URL, "synthetic-email-limits", ca)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	input := []byte("synthetic@example.invalid")
	raw, err := owner.RequestEmail(input)
	if err != nil {
		t.Fatal(err)
	}
	var reply map[string]any
	if json.Unmarshal([]byte(raw), &reply) != nil || reply["accepted"] != false || reply["trustedDevice"] != false || reply["retryAfterSeconds"] != float64(900) {
		t.Fatal("冷却未传递，或伪造接受/信任")
	}
	if !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("邮箱输入没有被消费")
	}
}
