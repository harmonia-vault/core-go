package accountreset

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/harmonia-vault/core-go/syncclient"
)

func TestEmailCodeResolveNormalizesCaseAndInternalProof(t *testing.T) {
	c := memoryClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/base/v1/account-reset/resolve" || r.URL.RawQuery != "" || r.Method != "POST" {
			t.Fatal("code not sent in the expected body-only route")
		}
		data, _ := io.ReadAll(r.Body)
		var input map[string]string
		if json.Unmarshal(data, &input) != nil || len(input) != 2 || input["code"] != "A2BC3DE4" || input["email"] != "synthetic@example.invalid" {
			t.Fatal("email/code changed before request")
		}
		response, _ := json.Marshal(proofFixture())
		return answer(200, string(response)), nil
	})
	got, err := c.ResolveCode(context.Background(), []byte(`{"email":"synthetic@example.invalid","code":"a2bc3de4"}`))
	if err != nil || got != proofFixture() {
		t.Fatal("internal proof not resolved", err)
	}
	for _, code := range []string{"123456", "23456789", "ABCDEFGH", "A2BC3D4", "A2BC3DE45", "A2BC3DE0", "A2BC3DE1", "A2BC3DEI", "A2BC3DEO", "ß2BC3DE", "Ａ2BC3DE4", " A2BC3DE4"} {
		data, _ := json.Marshal(map[string]string{"email": "synthetic@example.invalid", "code": code})
		if _, err := c.ResolveCode(context.Background(), data); !errors.Is(err, ErrInput) {
			t.Fatal("malformed code reached transport")
		}
	}
}

func TestEmailCodeServerLockIsPreserved(t *testing.T) {
	c := memoryClient(t, func(r *http.Request) (*http.Response, error) {
		return answer(429, `{"error":"email_code_attempts_exhausted"}`), nil
	})
	_, err := c.ResolveCode(context.Background(), []byte(`{"email":"synthetic@example.invalid","code":"B2CD3EF4"}`))
	var fault *syncclient.RequestError
	if !errors.As(err, &fault) || fault.Code != "email_code_attempts_exhausted" {
		t.Fatal("attempt limit lost across native boundary", err)
	}
}
