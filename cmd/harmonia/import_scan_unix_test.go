//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/localipc"
)

func TestProcessImportCannotBypassProtectedDaemonWithoutTrust(t *testing.T) {
	directory := protectedTestDirectory(t)
	store, err := protectedStore(protectedOptions{directory: directory})
	mustCLI(t, err)
	mustCLI(t, store.Close())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runWithRuntime(ctx, []string{"daemon", "--local-directory", directory, "--interval", "20ms", "--sync-interval", "1h"}, io.Discard, io.Discard, commandRuntime{})
	}()
	defer func() { cancel(); mustCLI(t, <-done) }()
	endpoint, err := ipcEndpoint(filepath.Join(directory, "ipc"), "", "")
	mustCLI(t, err)
	eventuallyCLI(t, func() bool {
		response, err := localipc.Call(context.Background(), endpoint, localipc.Request{Command: "status"})
		return err == nil && response.OK
	})
	source := syntheticProcessImportSource()
	var out, errOut bytes.Buffer
	err = runWithRuntime(ctx, []string{"import", "--local-directory", directory, "--current-env", "--environment", "env", "--select", "TOKEN", "--request-id", "scan-id"}, &out, &errOut, commandRuntime{environment: source})
	if err == nil || !reflectSelectedLookup(source.lookedUp) || strings.Contains(out.String()+errOut.String()+err.Error(), "synthetic-chosen") {
		t.Fatal("未入网扫描导入被接受、越界取值或泄露")
	}
	response, err := localipc.Call(context.Background(), endpoint, localipc.Request{Command: "status"})
	mustCLI(t, err)
	if !response.OK || response.Status.Environments != 0 || response.Status.Sequence != 0 {
		t.Fatal("拒绝导入后仍更新权威状态")
	}
}
func reflectSelectedLookup(names []string) bool { return len(names) == 1 && names[0] == "TOKEN" }
