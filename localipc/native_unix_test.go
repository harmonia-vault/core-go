//go:build darwin || linux

package localipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localstate"
)

func temporaryEndpoint(t *testing.T) Endpoint {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("本测试须普通本地用户；不以 root 伪装用户服务")
	}
	directory, err := os.MkdirTemp("/tmp", "harmonia-ipc-")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	must(t, os.Chmod(directory, 0700))
	directory, err = filepath.EvalSymlinks(directory)
	must(t, err)
	return Endpoint{Directory: directory, UserID: strconv.Itoa(os.Geteuid())}
}
func startServer(t *testing.T, endpoint Endpoint, engine *localstate.Engine, provider localstate.Provider) (*Server, context.CancelFunc, <-chan error) {
	t.Helper()
	return startObservedServer(t, endpoint, engine, provider, nil)
}
func startObservedServer(t *testing.T, endpoint Endpoint, engine *localstate.Engine, provider localstate.Provider, observe func(Diagnostic)) (*Server, context.CancelFunc, <-chan error) {
	t.Helper()
	server, err := Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider, Now: func() time.Time { return syntheticNow }, Timeout: time.Second, MaxConnections: 32, Observe: observe})
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	return server, cancel, done
}
func TestNativeUnixConcurrentClientsDisconnectAndRestart(t *testing.T) {
	endpoint := temporaryEndpoint(t)
	directory := filepath.Join(endpoint.Directory, "state")
	must(t, os.Mkdir(directory, 0700))
	store, err := localstate.OpenFileStore(filepath.Join(directory, "state.json"))
	must(t, err)
	engine, err := localstate.New(store)
	must(t, err)
	must(t, engine.EnableSyntheticFixtures())
	source, _, provider := fixture(t)
	must(t, engine.AcceptSnapshot(source.State().Cloud, syntheticNow))
	var timingMu sync.Mutex
	var maxQueue, maxExecution, maxElapsed time.Duration
	var terminal, timeouts, disconnects, otherFailures int
	observe := func(d Diagnostic) {
		if d.Stage == StageQueue {
			return
		}
		timingMu.Lock()
		defer timingMu.Unlock()
		terminal++
		switch d.Failure {
		case FailureNone:
		case FailureTimeout:
			timeouts++
		case FailureDisconnected:
			disconnects++
		default:
			otherFailures++
		}
		maxQueue = max(maxQueue, d.QueueWait)
		maxExecution = max(maxExecution, d.Execution)
		maxElapsed = max(maxElapsed, d.Elapsed)
	}
	t.Cleanup(func() {
		timingMu.Lock()
		defer timingMu.Unlock()
		t.Logf("连接终态=%d 超时=%d 断开=%d 其它失败=%d 最大排队毫秒=%d 最大执行毫秒=%d 最大总毫秒=%d 预算毫秒=1000 并发=20 容量=32", terminal, timeouts, disconnects, otherFailures, maxQueue.Milliseconds(), maxExecution.Milliseconds(), maxElapsed.Milliseconds())
	})
	server, cancel, done := startObservedServer(t, endpoint, engine, provider, observe)
	response, err := Call(context.Background(), endpoint, Request{Command: "activate", EnvironmentID: "one"})
	must(t, err)
	if !response.OK {
		t.Fatal(response)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			result, err := Call(context.Background(), endpoint, Request{Command: "status"})
			if err != nil || !result.OK {
				t.Error(result, err)
			}
		})
	}
	wg.Wait()
	// 一次 CLI 连接关闭，不会退出后台。
	connection, err := net.Dial("unix", filepath.Join(endpoint.Directory, socketName))
	must(t, err)
	_ = connection.Close()
	response, err = Call(context.Background(), endpoint, Request{Command: "export"})
	must(t, err)
	if !response.OK || response.Values["TOKEN"] != "synthetic-cloud" {
		t.Fatal(response)
	}
	info, err := os.Stat(filepath.Join(endpoint.Directory, socketName))
	must(t, err)
	if info.Mode().Perm() != 0600 {
		t.Fatal("socket permissions unsafe")
	}
	if second, err := Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider}); err == nil {
		_ = second.Close()
		t.Fatal("second owner accepted")
	}
	cancel()
	must(t, <-done)
	must(t, server.Close())
	must(t, store.Close())
	store, err = localstate.OpenFileStore(filepath.Join(directory, "state.json"))
	must(t, err)
	defer store.Close()
	engine, err = localstate.New(store)
	must(t, err)
	server, cancel, done = startServer(t, endpoint, engine, provider)
	defer func() { cancel(); must(t, <-done); must(t, server.Close()) }()
	response, err = Call(context.Background(), endpoint, Request{Command: "logout"})
	must(t, err)
	if !response.OK || provider.values["TOKEN"] != "original" || provider.values["UNRELATED"] != "keep" {
		t.Fatal(response, provider.values)
	}
}
func TestNativeUnixChecksPeerUIDAndRejectsOtherConfiguredUID(t *testing.T) {
	endpoint := temporaryEndpoint(t)
	engine, _, provider := fixture(t)
	server, cancel, done := startServer(t, endpoint, engine, provider)
	defer func() { cancel(); must(t, <-done); must(t, server.Close()) }()
	connection, err := net.Dial("unix", filepath.Join(endpoint.Directory, socketName))
	must(t, err)
	defer connection.Close()
	if err = authorizeNative(connection, endpoint, true); err != nil {
		t.Fatal("native peer credential check failed", err)
	}
	other := endpoint
	other.UserID = strconv.Itoa(os.Geteuid() + 1)
	if authorizeNative(connection, other, true) == nil {
		t.Fatal("different UID accepted")
	}
	if _, err = Call(context.Background(), other, Request{Command: "status"}); err == nil {
		t.Fatal("cross-UID endpoint accepted")
	}
}
func TestUnixRejectsPublicDirectorySymlinkAndExistingUserFile(t *testing.T) {
	endpoint := temporaryEndpoint(t)
	engine, _, provider := fixture(t)
	must(t, os.Chmod(endpoint.Directory, 0755))
	if _, err := Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider}); err == nil {
		t.Fatal("public directory accepted")
	}
	must(t, os.Chmod(endpoint.Directory, 0700))
	socketPath := filepath.Join(endpoint.Directory, socketName)
	must(t, os.WriteFile(socketPath, []byte("existing user file"), 0600))
	if _, err := Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider}); err == nil {
		t.Fatal("existing file overwritten")
	}
	data, err := os.ReadFile(socketPath)
	must(t, err)
	if string(data) != "existing user file" {
		t.Fatal("user file changed")
	}
	must(t, os.Remove(socketPath))
	target := filepath.Join(endpoint.Directory, "other")
	must(t, os.Mkdir(target, 0700))
	link := filepath.Join(endpoint.Directory, "link")
	must(t, os.Symlink(target, link))
	endpoint.Directory = link
	if _, err = Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider}); err == nil {
		t.Fatal("symlink directory accepted")
	}
}
func TestUnknownCloudPayloadCannotMutateEngine(t *testing.T) {
	endpoint := temporaryEndpoint(t)
	engine, _, provider := fixture(t)
	server, cancel, done := startServer(t, endpoint, engine, provider)
	defer func() { cancel(); must(t, <-done); must(t, server.Close()) }()
	connection, err := net.Dial("unix", filepath.Join(endpoint.Directory, socketName))
	must(t, err)
	defer connection.Close()
	packet := frame([]byte(`{"version":1,"command":"status","cloud":{"sequence":99}}`))
	_, err = connection.Write(packet)
	must(t, err)
	var response Response
	must(t, readFrame(connection, &response, maxResponseBytes))
	if response.OK || response.Code != "invalid_request" || engine.State().Cloud.Sequence != 1 {
		t.Fatal(response)
	}
}
func TestPartialFrameDisconnectDoesNotChangeState(t *testing.T) {
	endpoint := temporaryEndpoint(t)
	engine, _, provider := fixture(t)
	server, cancel, done := startServer(t, endpoint, engine, provider)
	defer func() { cancel(); must(t, <-done); must(t, server.Close()) }()
	connection, err := net.Dial("unix", filepath.Join(endpoint.Directory, socketName))
	must(t, err)
	_, err = connection.Write([]byte{0, 0, 0, 20, '{'})
	must(t, err)
	_ = connection.Close()
	response, err := Call(context.Background(), endpoint, Request{Command: "status"})
	must(t, err)
	if !response.OK || len(engine.State().Active) != 0 {
		t.Fatal("partial packet changed state")
	}
}

func TestUnixRejectsAncestorLinkAndMalformedOwnerMarker(t *testing.T) {
	endpoint := temporaryEndpoint(t)
	engine, _, provider := fixture(t)
	real := filepath.Join(endpoint.Directory, "real")
	must(t, os.Mkdir(real, 0700))
	alias := filepath.Join(endpoint.Directory, "alias")
	must(t, os.Symlink(real, alias))
	linked := endpoint
	linked.Directory = filepath.Join(alias, "ipc")
	if _, err := Listen(Config{Endpoint: linked, Engine: engine, Provider: provider}); err == nil {
		t.Fatal("ancestor symbolic link accepted")
	}
	if _, err := os.Stat(filepath.Join(real, "ipc")); !os.IsNotExist(err) {
		t.Fatal("linked ancestor was modified")
	}
	marker := filepath.Join(endpoint.Directory, "ipc-owner.json")
	for _, data := range []string{`{"schema":"harmonia/localipc/v1","uid":` + endpoint.UserID + `} {}`, `{"schema":"harmonia/localipc/v1","uid":` + endpoint.UserID + `,"extra":true}`, strings.Repeat("x", 4097)} {
		must(t, os.WriteFile(marker, []byte(data), 0600))
		if _, err := Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider}); err == nil {
			t.Fatal("malformed ownership marker accepted")
		}
	}
}
