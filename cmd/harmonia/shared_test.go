//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedInputSelectionExactBytesAndNoArgumentValues(t *testing.T) {
	input := "synthetic'\n$literal\n"
	request, err := sharedCLIRequest("put", "env", "TOKEN", "put-1", true, false, "", "", strings.NewReader(input))
	mustCLI(t, err)
	if request.Value == nil || *request.Value != input {
		t.Fatal("stdin bytes changed")
	}
	request, err = sharedCLIRequest("put", "env", "EMPTY", "empty-1", true, false, "", "", strings.NewReader(""))
	mustCLI(t, err)
	if *request.Value != "" {
		t.Fatal("empty value lost")
	}
	request, err = sharedCLIRequest("import", "env", "", "import-1", false, true, "", "CHOSEN", strings.NewReader(`{"CHOSEN":"synthetic-selected","NOT_CHOSEN":"synthetic-not-upload"}`))
	mustCLI(t, err)
	if len(request.Selected) != 1 || request.Selected["CHOSEN"] != "synthetic-selected" {
		t.Fatal("unselected input retained")
	}
	encoded, _ := json.Marshal(request)
	if bytes.Contains(encoded, []byte("NOT_CHOSEN")) || bytes.Contains(encoded, []byte("synthetic-not-upload")) {
		t.Fatal("unselected input reached IPC")
	}
	for _, input := range []string{string([]byte{0xff}), "nul\x00value", strings.Repeat("a", 65537)} {
		if _, err = readSharedInput(strings.NewReader(input)); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	directory := t.TempDir()
	for _, command := range []string{"put", "override-set"} {
		var out, errOut bytes.Buffer
		err = runWithRuntime(context.Background(), []string{command, "--local-directory", directory, "--environment", "env", "--name", "TOKEN", "--value", "synthetic-sensitive-argv"}, &out, &errOut, commandRuntime{})
		if err == nil || strings.Contains(err.Error()+out.String()+errOut.String(), "synthetic-sensitive-argv") {
			t.Fatal("argv secret accepted/echoed", command)
		}
	}
}
func TestExplicitCAKeepsChainAndHostnameVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "synthetic") }))
	defer server.Close()
	directory := t.TempDir()
	path := filepath.Join(directory, "synthetic-ca.pem")
	mustCLI(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600))
	client, err := clientWithCA(path)
	mustCLI(t, err)
	response, err := client.Get(server.URL)
	mustCLI(t, err)
	mustCLI(t, response.Body.Close())
	transport := client.Transport.(*http.Transport)
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	wrong := strings.Replace(server.URL, "127.0.0.1", "wrong.invalid", 1)
	if response, err = client.Get(wrong); err == nil {
		response.Body.Close()
		t.Fatal("custom CA disabled hostname verification")
	}
	mustCLI(t, os.WriteFile(path, []byte("not-a-certificate"), 0600))
	if _, err = clientWithCA(path); err == nil {
		t.Fatal("malformed CA accepted")
	}
}
