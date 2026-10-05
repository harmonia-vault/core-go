package mobileworkflow

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/syncclient"
)

// 真TLS响应中的任意小写串/hex不得通过公开Go错误或原生状态泄露。
func TestMobileHTTPSFaultCannotEchoPasswordEquivalentOrRemoteText(t *testing.T) {
	for _, body := range []string{`{"error":"synthetic_secret_lowercase"}`, `{"error":"` + strings.Repeat("a", 64) + `"}`, `{"error":"unauthorized","token":"synthetic"}`, `{"error":"unauthorized"} {}`, `{"error":"unauthorized","error":"device_untrusted"}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Harmonia-Protocol-Major", "2")

			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(body))
		}))
		config := testConfig(t)
		config.Endpoint, config.HTTPClient = server.URL, server.Client()
		workflow, err := New(config)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		_, err = workflow.Register(context.Background(), "synthetic@example.invalid", "synthetic-only-password")
		workflow.Close()
		server.Close()
		var fault *syncclient.RequestError
		if !errors.As(err, &fault) || fault.Code != "request_rejected" || strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), strings.Repeat("a", 64)) {
			t.Fatal("untrusted error body reached public native error")
		}
	}
}
