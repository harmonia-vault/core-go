package platform

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localstate"
)

func TestPausedPOSIXStopsCorrectionButAppliesRevocationFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX shell")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := localstate.OpenFileStore(filepath.Join(dir, "engine.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine, err := localstate.New(store)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "environment.sh")
	provider, err := NewPOSIXProvider(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	low := localstate.Environment{ID: "low", KeyVersion: 1, GrantGeneration: 1, Role: localstate.ReadOnly, Values: map[string]string{"TEST_KEY": "low-value"}}
	high := localstate.Environment{ID: "high", KeyVersion: 1, GrantGeneration: 1, Role: localstate.ReadOnly, Values: map[string]string{"TEST_KEY": "high-value"}}
	snapshot := localstate.CloudSnapshot{AccountID: "synthetic-account", AccountGeneration: 1, Sequence: 1, Environments: map[string]localstate.Environment{"low": low, "high": high}}
	if err := engine.AcceptSnapshot(snapshot, now); err != nil {
		t.Fatal(err)
	}
	if err := engine.Activate("low", 1, now); err != nil {
		t.Fatal(err)
	}
	if err := engine.Activate("high", 2, now); err != nil {
		t.Fatal(err)
	}
	saveFragment := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(dir, name)
		writeTestFile(t, dest, data)
		quoted, _ := ShellQuote(dest)
		return quoted
	}
	if err := engine.Reconcile(context.Background(), provider, now); err != nil {
		t.Fatal(err)
	}
	active := saveFragment("active.sh")
	if err := engine.SetPaused(true); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reconcile(context.Background(), provider, now); err != nil {
		t.Fatal(err)
	}
	paused := saveFragment("paused.sh")
	snapshot.Sequence = 2
	snapshot.Environments = map[string]localstate.Environment{"low": low}
	if err := engine.AcceptSnapshot(snapshot, now); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reconcile(context.Background(), provider, now); err != nil {
		t.Fatal(err)
	}
	fallback := saveFragment("fallback.sh")
	snapshot.Sequence = 3
	snapshot.Environments = map[string]localstate.Environment{}
	if err := engine.AcceptSnapshot(snapshot, now); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reconcile(context.Background(), provider, now); err != nil {
		t.Fatal(err)
	}
	released := saveFragment("released.sh")
	script := "set -eu\nTEST_KEY=original\nUNRELATED=keep\n. " + active + "\n[ \"$TEST_KEY\" = high-value ]\n. " + paused + "\nTEST_KEY=external-while-paused\n. " + paused + "\n[ \"$TEST_KEY\" = external-while-paused ]\n. " + fallback + "\n[ \"$TEST_KEY\" = low-value ]\nTEST_KEY=external-after-fallback\n. " + fallback + "\n[ \"$TEST_KEY\" = external-after-fallback ]\n. " + released + "\n[ \"$TEST_KEY\" = original ]\n[ \"$UNRELATED\" = keep ]\n"
	cmd := exec.Command(shell, "-c", script)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pause/revoke failed: %v %s", err, output)
	}
	// 暂停期间打开的新 shell 保留缓存配置，只应用一次。
	script = "set -eu\nTEST_KEY=new-shell-original\n. " + paused + "\n[ \"$TEST_KEY\" = high-value ]\nTEST_KEY=independent\n. " + paused + "\n[ \"$TEST_KEY\" = independent ]\n. " + released + "\n[ \"$TEST_KEY\" = new-shell-original ]\n"
	cmd = exec.Command(shell, "-c", script)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("new paused shell failed: %v %s", err, output)
	}
	provider, err = NewPOSIXProvider(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !provider.state.Paused || len(provider.state.Desired) != 0 {
		t.Fatal("pause or revoked cached value survived restart")
	}
}
