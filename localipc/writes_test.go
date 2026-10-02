package localipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localstate"
)

func TestSharedWhitelistAndMetadataOnlyResponse(t *testing.T) {
	store := &memoryStore{state: localstate.EmptyState()}
	engine, err := localstate.New(store)
	must(t, err)
	provider := &memoryProvider{values: map[string]string{}}
	var received SharedWriteRequest
	server := &Server{config: Config{Engine: engine, Provider: provider, Now: func() time.Time { return syntheticNow }, OnlineWrite: func(_ context.Context, r SharedWriteRequest) (SharedWriteResult, error) {
		received = r
		return SharedWriteResult{RequestID: r.RequestID, Total: len(r.Selected), Accepted: len(r.Selected), Applied: true, Sequences: []uint64{3}}, nil
	}}}
	response := server.dispatch(context.Background(), Request{Version: 1, Command: "import", EnvironmentID: "env", RequestID: "import-1", Selected: map[string]string{"SELECTED": "synthetic-only-input"}})
	if !response.OK || len(received.Selected) != 1 {
		t.Fatal(response)
	}
	wire, _ := json.Marshal(response)
	if bytes.Contains(wire, []byte("synthetic-only-input")) || bytes.Contains(wire, []byte("SELECTED")) {
		t.Fatal("shared response leaked values or variable names")
	}
	server.config.OnlineWrite = func(context.Context, SharedWriteRequest) (SharedWriteResult, error) {
		return SharedWriteResult{RequestID: "error-1"}, errors.New("SYNTHETIC_SECRET_ERROR")
	}
	response = server.dispatch(context.Background(), Request{Version: 1, Command: "delete", EnvironmentID: "env", Name: "KEY", RequestID: "error-1"})
	wire, _ = json.Marshal(response)
	if response.OK || bytes.Contains(wire, []byte("SYNTHETIC_SECRET_ERROR")) {
		t.Fatal("raw write error leaked")
	}
	bad := []Request{{Version: 1, Command: "put", EnvironmentID: "env", Name: "KEY", RequestID: "p"}, {Version: 1, Command: "status", Selected: map[string]string{"KEY": "synthetic"}}, {Version: 1, Command: "delete", EnvironmentID: "env", Name: "KEY", RequestID: "p", Value: ptr("unexpected")}, {Version: 1, Command: "write-retry", RequestID: "p", Selected: map[string]string{"KEY": "unexpected"}}, {Version: 1, Command: "import", EnvironmentID: "env", RequestID: "p", Selected: map[string]string{"__harmonia_reserved": "synthetic"}}, {Version: 1, Command: "put", EnvironmentID: "env", Name: "KEY", RequestID: "p", Value: ptr(strings.Repeat("x", 65537))}}
	for _, request := range bad {
		if validateRequest(request) == nil {
			t.Fatal("shared input allowed unexpected fields")
		}
	}
	must(t, engine.EnableSyntheticFixtures())
	response = server.dispatch(context.Background(), Request{Version: 1, Command: "delete", EnvironmentID: "env", Name: "KEY", RequestID: "fixture"})
	if response.OK || response.Code != "shared_write_unavailable" {
		t.Fatal("fixture wrote shared state")
	}
}
