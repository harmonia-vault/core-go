package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/localstate"
)

func commandTest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := run(context.Background(), args, &out, &errOut)
	return out.String(), err
}
func fixtureCLI(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "cloud.json")
	snapshot := localstate.CloudSnapshot{AccountID: "synthetic", AccountGeneration: 1, Sequence: 1, Environments: map[string]localstate.Environment{"one": {ID: "one", KeyVersion: 1, GrantGeneration: 1, Role: localstate.ReadWrite, Values: map[string]string{"TOKEN": "synthetic-cloud", "ADDED": "synthetic-added"}}}}
	data, _ := json.Marshal(snapshot)
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state.json")
	if _, err := commandTest(t, "fixture-load", "--state", state, "--input", input, "--fixture"); err != nil {
		t.Fatal(err)
	}
	return state, filepath.Join(dir, "environment.json")
}
func TestCLIFixtureActivationOverrideAndLogout(t *testing.T) {
	state, provider := fixtureCLI(t)
	if err := os.WriteFile(provider, []byte(`{"TOKEN":"original","UNRELATED":"keep"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := commandTest(t, "activate", "--state", state, "--fixture", "--environment", "one", "--priority", "3", "--provider-file", provider); err != nil {
		t.Fatal(err)
	}
	if _, err := commandTest(t, "override-set", "--state", state, "--fixture", "--environment", "one", "--name", "TOKEN", "--value", "local", "--provider-file", provider); err != nil {
		t.Fatal(err)
	}
	out, err := commandTest(t, "export", "--state", state, "--fixture")
	if err != nil || !strings.Contains(out, "export TOKEN='local'") {
		t.Fatal(out, err)
	}
	status, err := commandTest(t, "status", "--state", state, "--fixture")
	if err != nil || strings.Contains(status, "synthetic-cloud") || strings.Contains(status, "local") {
		t.Fatal("status leaked values", status, err)
	}
	if _, err = commandTest(t, "logout", "--state", state, "--fixture", "--provider-file", provider); err != nil {
		t.Fatal(err)
	}
	var restored map[string]string
	data, _ := os.ReadFile(provider)
	if err = json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored, map[string]string{"TOKEN": "original", "UNRELATED": "keep"}) {
		t.Fatal(restored)
	}
}
func TestFixtureCannotSilentlyBecomeTrusted(t *testing.T) {
	state, _ := fixtureCLI(t)
	if _, err := commandTest(t, "status", "--state", state); err == nil {
		t.Fatal("fixture flag required")
	}
	if _, err := commandTest(t, "daemon", "--state", state, "--fixture", "--once"); err == nil {
		t.Fatal("implicit real provider accepted")
	}
	if _, err := commandTest(t, "login"); err == nil {
		t.Fatal("unfinished production login accepted")
	}
}
func TestDaemonOnceReconcilesOnlyIsolatedProvider(t *testing.T) {
	state, provider := fixtureCLI(t)
	if _, err := commandTest(t, "activate", "--state", state, "--fixture", "--environment", "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := commandTest(t, "daemon", "--state", state, "--fixture", "--provider-file", provider, "--once"); err != nil {
		t.Fatal(err)
	}
	var applied map[string]string
	data, _ := os.ReadFile(provider)
	_ = json.Unmarshal(data, &applied)
	if applied["TOKEN"] != "synthetic-cloud" {
		t.Fatal(applied)
	}
}
func TestExplicitSelectedImport(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "candidates.json")
	if err := os.WriteFile(input, []byte(`{"CHOSEN":"yes","OTHER":"do-not-upload"}`), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := commandTest(t, "import-preview", "--from", input, "--select", "CHOSEN")
	if err != nil || strings.Contains(out, "OTHER") || !strings.Contains(out, "CHOSEN") {
		t.Fatal(out, err)
	}
	if _, err = commandTest(t, "import-preview", "--from", input); err == nil {
		t.Fatal("implicit selection allowed")
	}
}
func TestExportQuotesValueWithoutShellExecution(t *testing.T) {
	state, _ := fixtureCLI(t)
	literal := "quote' $(never-run) `never-run`\nline"
	if _, err := commandTest(t, "activate", "--state", state, "--fixture", "--environment", "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := commandTest(t, "override-set", "--state", state, "--fixture", "--environment", "one", "--name", "TOKEN", "--value", literal); err != nil {
		t.Fatal(err)
	}
	out, err := commandTest(t, "export", "--state", state, "--fixture")
	if err != nil || !strings.Contains(out, "'\\''") {
		t.Fatal(out, err)
	}
}
func TestExecCompositionUsesSyntheticBaseAndRestoresOnlyManagedNames(t *testing.T) {
	composed := composeEnvironment([]string{"TOKEN=external", "UNRELATED=keep", "ADDED=old"}, map[string]string{"TOKEN": "cloud"}, map[string]localstate.Original{"TOKEN": {Present: true, Value: "original"}, "ADDED": {Present: false}})
	if !reflect.DeepEqual(composed, []string{"TOKEN=cloud", "UNRELATED=keep"}) {
		t.Fatal(composed)
	}
	restored := composeEnvironment([]string{"TOKEN=cloud", "UNRELATED=keep"}, map[string]string{}, map[string]localstate.Original{"TOKEN": {Present: true, Value: "original"}})
	if !reflect.DeepEqual(restored, []string{"TOKEN=original", "UNRELATED=keep"}) {
		t.Fatal(restored)
	}
}
func TestUnknownArgumentsAndMissingInputFail(t *testing.T) {
	if _, err := commandTest(t, "fixture-load", "--state", filepath.Join(t.TempDir(), "state.json"), "--fixture"); err == nil {
		t.Fatal("missing fixture input allowed")
	}
	if _, err := commandTest(t, "status", "--unexpected"); err == nil {
		t.Fatal("unknown flag accepted")
	}
}
