package syncclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/localstate"
)

func TestServerFaultSeparatesTokenExpiryFromAuthorityInvalidation(t *testing.T) {
	for _, tt := range []struct {
		status  int
		code    string
		invalid bool
		boot    bool
	}{
		{401, "unauthorized", false, false}, {401, "generation_stale", true, false},
		{403, "device_untrusted", true, false}, {403, "no_current_grant", false, false},
		{403, "no_current_grant", true, true}, {403, "challenge_invalid", false, true}, {403, "signature_invalid", false, true},
	} {
		t.Run(tt.code+fmtInt(int64(tt.status))+fmtInt(boolInt(tt.boot)), func(t *testing.T) {
			engine := testEngine(t)
			cloud, err := (acceptVerifier{}).VerifyPull(context.Background(), Pull{Sequence: 1}, localstate.CloudSnapshot{})
			check(t, err)
			check(t, engine.AcceptSnapshot(cloud, fixedNow))
			epoch := engine.State().SessionEpoch
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Harmonia-Protocol-Major", "2")

				w.Header().Set("Harmonia-Protocol-Major", "2")
				w.WriteHeader(tt.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": tt.code})
			}))
			defer server.Close()
			client := testClient(t, server, engine, acceptVerifier{})
			var out any
			route := "/pull"
			if tt.boot {
				route = "/boot-challenges"
			}
			err = client.request(context.Background(), "POST", client.endpointFor(route), struct{}{}, &out)
			if errors.Is(err, ErrTrustInvalidated) != tt.invalid {
				t.Fatal(err)
			}
			state := engine.State()
			if tt.invalid {
				if len(state.Cloud.Environments) != 0 || state.SessionEpoch != epoch+1 {
					t.Fatal("rejected authorization retained cache")
				}
			} else if state.Cloud.Sequence != 1 || state.SessionEpoch != epoch {
				t.Fatal("ordinary session failure cleared offline authority")
			}
		})
	}
}
func boolInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
func TestRejectedBodyCannotLeakValuesOrInjectIdentity(t *testing.T) {
	for _, body := range []string{`{"error":"SYNTHETIC_SECRET"}`, `{"error":"synthetic_secret_lowercase"}`, `{"error":"` + strings.Repeat("a", 64) + `"}`, `{"error":"device_untrusted","accountId":"attacker"}`, `{"error":"unauthorized","error":"device_untrusted"}`, `{"error":"device_untrusted","retryAfterSeconds":null}`, "{\"error\":\"device_\xffuntrusted\"}", `{"error":"device_untrusted"} {}`, strings.Repeat("SYNTHETIC_SECRET", 500)} {
		engine := testEngine(t)
		cloud, err := (acceptVerifier{}).VerifyPull(context.Background(), Pull{Sequence: 1}, localstate.CloudSnapshot{})
		check(t, err)
		check(t, engine.AcceptSnapshot(cloud, fixedNow))
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Harmonia-Protocol-Major", "2")

			w.Header().Set("Harmonia-Protocol-Major", "2")
			w.WriteHeader(403)
			_, _ = w.Write([]byte(body))
		}))
		client := testClient(t, server, engine, acceptVerifier{})
		_, err = client.Pull(context.Background())
		server.Close()
		var rejected *RequestError
		if err == nil || !errors.As(err, &rejected) || rejected.Code != "request_rejected" || strings.Contains(err.Error(), "SYNTHETIC_SECRET") || errors.Is(err, ErrTrustInvalidated) || engine.State().Cloud.Sequence != 1 {
			t.Fatal(err)
		}
	}
}
func TestOldRejectedEpochCannotClearNewContext(t *testing.T) {
	engine := testEngine(t)
	epoch := engine.State().SessionEpoch
	check(t, engine.Logout())
	cloud, err := (acceptVerifier{}).VerifyPull(context.Background(), Pull{Sequence: 1}, localstate.CloudSnapshot{})
	check(t, err)
	check(t, engine.AcceptSnapshot(cloud, fixedNow))
	if !errors.Is(engine.LogoutAtEpoch(epoch), localstate.ErrLocalSession) || engine.State().Cloud.Sequence != 1 {
		t.Fatal("old rejection cleared current account")
	}
}
