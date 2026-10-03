package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

type resolutionForbiddenTransport struct{ posts int }

func (r *resolutionForbiddenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.posts++
	return nil, errors.New("synthetic forbidden network")
}
func TestRecoveryOperationNarrowSessionUnsupportedZeroPOST(t *testing.T) {
	raw, e := os.ReadFile("../cryptox/testdata/recovery-operation-resolution-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Requests []struct {
			Request cryptox.RecoveryOperationResolutionRequest `json:"request"`
		} `json:"requests"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public vectors")
	}
	base := f.Requests[0].Request.Target
	for _, mode := range []string{"recovered", "all-admin", "intent", "challenged"} {
		t.Run(mode, func(t *testing.T) {
			target := base
			switch mode {
			case "recovered":
				target.Kind = "recovered-v2"
			case "all-admin":
				target.AuthorizationKind = "all-admin"
			case "intent":
				target.Stage = "intent"
			case "challenged":
				target.Stage = "challenged"
			}
			transport := &resolutionForbiddenTransport{}
			s := &RecoveryOperationResolutionSession{session: &DAGRecoverySession{http: &http.Client{Transport: transport}}}
			if _, e := s.Resolve(context.Background(), target, "resolve-or-close", nil); !errors.Is(e, ErrRecoveryResolutionUnsupported) || transport.posts != 0 {
				t.Fatal("unsupported reached POST", e)
			}
		})
	}
}

type resolutionResponseTransport struct {
	body  []byte
	major string
	posts int
}

func (r *resolutionResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.posts++
	if request.URL.RawQuery != "capability="+cryptox.RecoveryOperationClosureCapability || request.Header.Get("Harmonia-Protocol-Major") != "2" {
		return nil, errors.New("synthetic request contract")
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Harmonia-Protocol-Major": []string{r.major}}, Body: io.NopCloser(bytes.NewReader(r.body))}, nil
}
func TestRecoveryOperationSessionExactReceiptAndNoMetadataAuthority(t *testing.T) {
	raw, e := os.ReadFile("../cryptox/testdata/recovery-operation-resolution-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Seed     string `json:"syntheticSigningSeedHex"`
		Requests []struct {
			Request cryptox.RecoveryOperationResolutionRequest `json:"request"`
		} `json:"requests"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public vector")
	}
	var target cryptox.RecoveryOperationTarget
	for _, v := range f.Requests {
		if v.Request.Target.Stage == "sealed" && v.Request.Target.Kind == "transition-v2" && v.Request.Target.AuthorizationKind == "old-recovery" {
			target = v.Request.Target
			break
		}
	}
	if target.OperationID == "" {
		t.Fatal("sealed public target")
	}
	seed, e := hex.DecodeString(f.Seed)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	hash, _ := target.Hash()
	good := cryptox.RecoveryOperationResolutionReceipt{Version: 1, Profile: cryptox.RecoveryOperationResolutionProfile, AccountID: target.AccountID, AccountGeneration: target.AccountGeneration, Kind: target.Kind, OperationID: target.OperationID, TargetHash: hash, State: "pending"}
	body, e := json.Marshal(good)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"valid-pending", "major", "extra", "different-target", "wrong-state", "duplicate", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			value := bytes.Clone(body)
			major := "2"
			var m map[string]any
			_ = json.Unmarshal(value, &m)
			switch mode {
			case "major":
				major = "1"
			case "extra":
				m["trustedDevice"] = true
			case "different-target":
				m["operationId"] = "other-original"
			case "wrong-state":
				m["state"] = "expired"
			case "duplicate":
				value = bytes.Replace(value, []byte(`"state":"pending"`), []byte(`"state":"pending","state":"pending"`), 1)
			case "oversize":
				value = []byte(strings.Repeat(" ", 4097))
			}
			if mode == "extra" || mode == "different-target" || mode == "wrong-state" {
				value, _ = json.Marshal(m)
			}
			tr := &resolutionResponseTransport{body: value, major: major}
			u, _ := url.Parse("https://synthetic.invalid")
			s := &RecoveryOperationResolutionSession{session: &DAGRecoverySession{config: DAGRecoveryConfig{Endpoint: u.String(), AccountID: target.AccountID, AccountGeneration: 1, Now: time.Now}, endpoint: u, http: &http.Client{Transport: tr}, token: strings.Repeat("T", 32), expires: time.Now().Unix() + 60}}
			out, e := s.Resolve(context.Background(), target, "query", key)
			s.Close()
			if mode == "valid-pending" {
				if e != nil || out.State != "pending" {
					t.Fatal("valid receipt", e)
				}
			} else if e == nil {
				t.Fatal("invalid receipt accepted")
			}
			if tr.posts != 1 {
				t.Fatal("unexpected original network count", tr.posts)
			}
		})
	}
}
