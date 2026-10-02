package localipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localstate"
)

var syntheticNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type memoryStore struct {
	mu    sync.Mutex
	state localstate.State
}

func (s *memoryStore) Load() (localstate.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, nil
}
func (s *memoryStore) Save(state localstate.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	return nil
}

type memoryProvider struct {
	values map[string]string
	failed bool
}

func (p *memoryProvider) Snapshot(_ context.Context, names []string) (map[string]string, error) {
	if p.failed {
		return nil, errors.New("SYNTHETIC_SECRET_PROVIDER_FAILURE")
	}
	out := map[string]string{}
	for _, name := range names {
		if value, ok := p.values[name]; ok {
			out[name] = value
		}
	}
	return out, nil
}
func (p *memoryProvider) Apply(_ context.Context, changes []localstate.Change) error {
	for _, c := range changes {
		if c.Value == nil {
			delete(p.values, c.Name)
		} else {
			p.values[c.Name] = *c.Value
		}
	}
	return nil
}
func fixture(t *testing.T) (*localstate.Engine, *memoryStore, *memoryProvider) {
	t.Helper()
	store := &memoryStore{state: localstate.EmptyState()}
	engine, err := localstate.New(store)
	must(t, err)
	must(t, engine.EnableSyntheticFixtures())
	must(t, engine.AcceptSnapshot(localstate.CloudSnapshot{AccountID: "synthetic", AccountGeneration: 1, Sequence: 1, Environments: map[string]localstate.Environment{"one": {ID: "one", KeyVersion: 1, GrantGeneration: 1, Role: localstate.ReadWrite, Values: map[string]string{"TOKEN": "synthetic-cloud", "ADDED": "synthetic-added"}}}}, syntheticNow))
	provider := &memoryProvider{values: map[string]string{"TOKEN": "original", "UNRELATED": "keep"}}
	return engine, store, provider
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func TestWhitelistRejectsTrustAndUnexpectedArguments(t *testing.T) {
	bad := []Request{{Version: 1, Command: "fixture-load"}, {Version: 1, Command: "accept-snapshot"}, {Version: 1, Command: "grant"}, {Version: 1, Command: "login"}, {Version: 1, Command: "status", Value: ptr("SYNTHETIC_SECRET")}, {Version: 1, Command: "override-set", EnvironmentID: "one", Name: "__harmonia_internal", Value: ptr("x")}, {Version: 2, Command: "status"}}
	for _, request := range bad {
		if validateRequest(request) == nil {
			t.Fatal("non-whitelist request accepted")
		}
	}
}
func TestFramingRejectsOversizeTruncatedUnknownFieldsAndExtraJSON(t *testing.T) {
	cases := [][]byte{frame([]byte(`{"version":1,"command":"status","cloud":{"secret":"never-read"}}`)), frame([]byte(`{"version":1,"command":"status"} {}`)), {0, 0, 0, 10, '{'}, {0xff, 0xff, 0xff, 0xff}}
	for _, packet := range cases {
		var request Request
		if readFrame(bytes.NewReader(packet), &request, maxRequestBytes) == nil {
			t.Fatal("malformed frame accepted")
		}
	}
}
func TestStatusAndErrorsDoNotContainVariableValues(t *testing.T) {
	engine, _, provider := fixture(t)
	server := &Server{config: Config{Engine: engine, Provider: provider, Now: func() time.Time { return syntheticNow }}}
	response := server.dispatch(context.Background(), Request{Version: 1, Command: "activate", EnvironmentID: "one"})
	if !response.OK {
		t.Fatal(response)
	}
	var buffer bytes.Buffer
	must(t, writeFrame(&buffer, response, maxResponseBytes))
	if strings.Contains(buffer.String(), "synthetic-cloud") || strings.Contains(buffer.String(), "original") {
		t.Fatal("status leaked a value")
	}
	provider.failed = true
	response = server.dispatch(context.Background(), Request{Version: 1, Command: "logout"})
	buffer.Reset()
	must(t, writeFrame(&buffer, response, maxResponseBytes))
	if response.OK || strings.Contains(buffer.String(), "SYNTHETIC_SECRET") || len(engine.State().Cloud.Environments) != 0 {
		t.Fatal("failure leaked values or failed to clear cloud authority")
	}
}
func TestSerializedConcurrentCommandsAndOriginalRecovery(t *testing.T) {
	engine, _, provider := fixture(t)
	server := &Server{config: Config{Engine: engine, Provider: provider, Now: func() time.Time { return syntheticNow }}}
	if response := server.dispatch(context.Background(), Request{Version: 1, Command: "activate", EnvironmentID: "one"}); !response.OK {
		t.Fatal(response)
	}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			value := fmt.Sprintf("synthetic-%d", i)
			response := server.dispatch(context.Background(), Request{Version: 1, Command: "override-set", EnvironmentID: "one", Name: "TOKEN", Value: &value})
			if !response.OK {
				t.Error(response)
			}
		})
	}
	wg.Wait()
	response := server.dispatch(context.Background(), Request{Version: 1, Command: "export"})
	if !response.OK || !strings.HasPrefix(response.Values["TOKEN"], "synthetic-") {
		t.Fatal(response)
	}
	if response = server.dispatch(context.Background(), Request{Version: 1, Command: "deactivate", EnvironmentID: "one"}); !response.OK {
		t.Fatal(response)
	}
	if provider.values["TOKEN"] != "original" || provider.values["UNRELATED"] != "keep" {
		t.Fatal(provider.values)
	}
	if _, exists := provider.values["ADDED"]; exists {
		t.Fatal("tool-added key retained")
	}
}
func TestPriorityCannotImplicitlyActivateAndOverrideCannotCreateCloudKey(t *testing.T) {
	engine, _, provider := fixture(t)
	server := &Server{config: Config{Engine: engine, Provider: provider, Now: func() time.Time { return syntheticNow }}}
	priority := 10
	if response := server.dispatch(context.Background(), Request{Version: 1, Command: "priority", EnvironmentID: "one", Priority: &priority}); response.OK || response.Code != "inactive_environment" {
		t.Fatal(response)
	}
	if response := server.dispatch(context.Background(), Request{Version: 1, Command: "override-set", EnvironmentID: "one", Name: "MISSING", Value: ptr("x")}); response.OK {
		t.Fatal(response)
	}
}
func TestPauseAndReceivedRevocationUseSameBackgroundEngine(t *testing.T) {
	engine, _, provider := fixture(t)
	server := &Server{config: Config{Engine: engine, Provider: provider, Now: func() time.Time { return syntheticNow }}}
	if !server.dispatch(context.Background(), Request{Version: 1, Command: "activate", EnvironmentID: "one"}).OK {
		t.Fatal("activate failed")
	}
	if !server.dispatch(context.Background(), Request{Version: 1, Command: "pause"}).OK {
		t.Fatal("pause failed")
	}
	provider.values["TOKEN"] = "external-paused"
	must(t, server.Reconcile(context.Background(), syntheticNow))
	if provider.values["TOKEN"] != "external-paused" {
		t.Fatal("pause corrected edit")
	}
	must(t, engine.AcceptSnapshot(localstate.CloudSnapshot{AccountID: "synthetic", AccountGeneration: 1, Sequence: 2, Environments: map[string]localstate.Environment{}}, syntheticNow))
	must(t, server.Reconcile(context.Background(), syntheticNow))
	if provider.values["TOKEN"] != "original" {
		t.Fatal("paused revocation did not restore")
	}
}
func frame(data []byte) []byte {
	packet := make([]byte, 4, len(data)+4)
	binary.BigEndian.PutUint32(packet, uint32(len(data)))
	return append(packet, data...)
}
func ptr(value string) *string { return &value }

func TestLogoutCleanupHookRunsAfterCacheClearAndBeforeRestoration(t *testing.T) {
	engine, _, provider := fixture(t)
	hookCalled := false
	server := &Server{config: Config{Engine: engine, Provider: provider, Now: func() time.Time { return syntheticNow }, OnLogout: func(context.Context) error {
		hookCalled = true
		if engine.State().Cloud.AccountID != "" || len(engine.State().Managed) != 0 {
			t.Error("cleanup callback saw cached cloud authority")
		}
		if provider.values["TOKEN"] != "synthetic-cloud" {
			t.Error("restoration unexpectedly preceded stopping old sync")
		}
		return nil
	}}}
	if !server.dispatch(context.Background(), Request{Version: 1, Command: "activate", EnvironmentID: "one"}).OK {
		t.Fatal("activate failed")
	}
	response := server.dispatch(context.Background(), Request{Version: 1, Command: "logout"})
	if !response.OK || !hookCalled || provider.values["TOKEN"] != "original" {
		t.Fatal(response)
	}
}
