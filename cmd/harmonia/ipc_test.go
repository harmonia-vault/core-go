//go:build darwin || linux

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localipc"
	"github.com/harmonia-vault/core-go/localstate"
)

func TestCLICommandsRunWhileDaemonOwnsStateFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("IPC daemon测试使用普通本地用户")
	}
	state, provider := fixtureCLI(t)
	if err := os.WriteFile(provider, []byte(`{"TOKEN":"original","UNRELATED":"keep"}`), 0600); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/tmp", "harmonia-cli-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		err := run(ctx, []string{"daemon", "--fixture", "--state", state, "--provider-file", provider, "--ipc-dir", directory, "--interval", "20ms"}, io.Discard, io.Discard)
		done <- err
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	endpoint, err := ipcEndpoint(directory, "", "")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		response, err := localipc.Call(context.Background(), endpoint, localipc.Request{Command: "status"})
		if err == nil && response.OK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon IPC did not start", err)
		}
		time.Sleep(time.Millisecond)
	}
	if second, err := localstate.OpenFileStore(state); err == nil {
		_ = second.Close()
		t.Fatal("daemon did not retain exclusive state ownership")
	}
	if _, err = commandTest(t, "activate", "--fixture", "--ipc-dir", directory, "--environment", "one", "--priority", "7"); err != nil {
		t.Fatal(err)
	}
	if _, err = commandTest(t, "override-set", "--fixture", "--ipc-dir", directory, "--environment", "one", "--name", "TOKEN", "--value", "synthetic-rpc"); err != nil {
		t.Fatal(err)
	}
	exports, err := commandTest(t, "export", "--fixture", "--ipc-dir", directory)
	if err != nil || !strings.Contains(exports, "export TOKEN='synthetic-rpc'") {
		t.Fatal(exports, err)
	}
	if _, err = commandTest(t, "pause", "--fixture", "--ipc-dir", directory); err != nil {
		t.Fatal(err)
	}
	status, err := commandTest(t, "status", "--fixture", "--ipc-dir", directory)
	if err != nil || !strings.Contains(status, `"paused":true`) {
		t.Fatal(status, err)
	}
	if _, err = commandTest(t, "logout", "--fixture", "--ipc-dir", directory); err != nil {
		t.Fatal(err)
	}
	values, err := (&localstate.FileProvider{Path: provider}).Snapshot(context.Background(), []string{"TOKEN", "UNRELATED", "ADDED"})
	if err != nil || values["TOKEN"] != "original" || values["UNRELATED"] != "keep" {
		t.Fatal(values, err)
	}
	if _, ok := values["ADDED"]; ok {
		t.Fatal("logout retained added variable")
	}
	// CLI 退出账号和连接关闭，不会停止 daemon 或释放状态独占锁。
	if _, err = commandTest(t, "status", "--fixture", "--ipc-dir", directory); err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(directory) != directory {
		t.Fatal("fixture IPC path not canonical")
	}
}
