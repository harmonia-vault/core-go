//go:build darwin || linux

package localipc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localstate"
)

// gatedFileStore 仍执行真实 FileStore 的 Save/fsync；仅人为控制首次 Save 的完成时间。
type gatedFileStore struct {
	localstate.Store
	armed   atomic.Bool
	saves   atomic.Int32
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *gatedFileStore) Save(state localstate.State) error {
	if s.armed.Load() {
		s.saves.Add(1)
		s.once.Do(func() { close(s.entered); <-s.release })
	}
	return s.Store.Save(state)
}
func awaitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(4 * time.Second):
		t.Fatal("受控 IPC 阶段未到达")
	}
}

func TestNativeUnixQueuedDeadlineRejectsExpiredMutation(t *testing.T) {
	endpoint := temporaryEndpoint(t)
	directory := filepath.Join(endpoint.Directory, "state")
	must(t, os.Mkdir(directory, 0700))
	file, err := localstate.OpenFileStore(filepath.Join(directory, "state.json"))
	must(t, err)
	defer file.Close()
	store := &gatedFileStore{Store: file, entered: make(chan struct{}), release: make(chan struct{})}
	var released sync.Once
	release := func() { released.Do(func() { close(store.release) }) }
	defer release()
	engine, err := localstate.New(store)
	must(t, err)
	must(t, engine.EnableSyntheticFixtures())
	source, _, provider := fixture(t)
	must(t, engine.AcceptSnapshot(source.State().Cloud, syntheticNow))
	must(t, engine.Activate("one", 0, syntheticNow))
	must(t, engine.Reconcile(context.Background(), provider, syntheticNow))
	store.armed.Store(true)
	var observedMu sync.Mutex
	var observed []Diagnostic
	queued := make(chan struct{})
	var queues atomic.Int32
	server, err := Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider, Now: func() time.Time { return syntheticNow }, Timeout: time.Second, MaxConnections: 32, Observe: func(d Diagnostic) {
		observedMu.Lock()
		observed = append(observed, d)
		observedMu.Unlock()
		if d.Stage == StageQueue && queues.Add(1) == 2 {
			close(queued)
		}
	}})
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	stopped := false
	defer func() {
		release()
		cancel()
		if !stopped {
			must(t, <-done)
		}
		must(t, server.Close())
	}()
	first := make(chan error, 1)
	go func() { _, err := Call(context.Background(), endpoint, Request{Command: "status"}); first <- err }()
	awaitSignal(t, store.entered)
	second := make(chan error, 1)
	go func() {
		_, err := Call(context.Background(), endpoint, Request{Command: "override-set", EnvironmentID: "one", Name: "TOKEN", Value: ptr("synthetic-queued-value")})
		second <- err
	}()
	awaitSignal(t, queued)
	// 两条完整请求均已进入服务；预算不变，模拟 fsync 被磁盘/调度阻塞超出 1 秒。
	<-time.NewTimer(1100 * time.Millisecond).C
	// 排队者须在首个 fsync 尚未释放时返回，不能只在最后取得锁时拒绝。
	select {
	case err := <-second:
		requireTransport(t, err, PhaseReadHeader, FailureDisconnected)
	case <-time.After(time.Second):
		t.Fatal("过期排队连接仍等待正在执行的持久化")
	}
	release()
	for _, result := range []<-chan error{first} {
		select {
		case err := <-result:
			var transport *TransportError
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrProtocol) || !errors.As(err, &transport) || transport.Phase != PhaseReadHeader || transport.Failure != FailureDisconnected {
				t.Fatalf("超时关闭未归为固定传输类别: %T", err)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("客户端没有在截止后返回")
		}
	}
	cancel()
	must(t, <-done)
	stopped = true
	must(t, server.Close())
	// 完整 Close 后再读观察器，确保它与 worker 的生命周期一致。
	observedMu.Lock()
	defer observedMu.Unlock()
	var terminal []Diagnostic
	for _, d := range observed {
		if d.Stage != StageQueue {
			terminal = append(terminal, d)
		}
	}
	if len(terminal) != 2 {
		t.Fatalf("连接终态数=%d", len(terminal))
	}
	var started, rejected int
	for _, d := range terminal {
		t.Logf("阶段=%s 类别=%s 排队毫秒=%d 执行毫秒=%d 总毫秒=%d 预算毫秒=%d 已开始=%t 业务成功=%t", d.Stage, d.Failure, d.QueueWait.Milliseconds(), d.Execution.Milliseconds(), d.Elapsed.Milliseconds(), d.Budget.Milliseconds(), d.ExecutionStarted, d.ResponseOK)
		if d.Stage != StageResponseHeader || d.Failure != FailureTimeout || d.Elapsed < d.Budget {
			t.Fatal("未观察到预算耗尽后的响应头超时")
		}
		if d.ExecutionStarted {
			started++
			if !d.ResponseOK || d.Execution < d.Budget {
				t.Fatal("已开始操作的持久化被跳过")
			}
		} else {
			rejected++
			if d.ResponseOK || d.QueueWait < 900*time.Millisecond || d.Execution != 0 {
				t.Fatal("排队截止没有阻止执行")
			}
		}
	}
	if started != 1 || rejected != 1 {
		t.Fatal("排队与已执行操作未区分")
	}
	if len(engine.State().Overrides) != 0 {
		t.Fatal("过期排队请求修改了状态")
	}
	if store.saves.Load() != 2 {
		t.Fatalf("真实持久化次数=%d，期望只有已开始 status 的两次", store.saves.Load())
	}
	t.Logf("真实 Save/fsync 次数=%d；过期排队操作未执行", store.saves.Load())
}

func TestNativeUnixCapacityRejectIsUnavailableNotProtocol(t *testing.T) {
	endpoint := temporaryEndpoint(t)
	engine, _, provider := fixture(t)
	capacity := make(chan struct{})
	var once sync.Once
	server, err := Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider, Timeout: time.Second, MaxConnections: 1, Observe: func(d Diagnostic) {
		if d.Stage == StageAdmission && d.Failure == FailureCapacity {
			once.Do(func() { close(capacity) })
		}
	}})
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() { cancel(); must(t, <-done); must(t, server.Close()) }()
	held, err := net.Dial("unix", filepath.Join(endpoint.Directory, socketName))
	must(t, err)
	defer held.Close()
	// 等第一连接确实占用 slot，避免以调度先后猜测 admission。
	ready := time.NewTimer(time.Second)
	defer ready.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		server.connections.Lock()
		occupied := len(server.open) == 1
		server.connections.Unlock()
		if occupied {
			break
		}
		select {
		case <-tick.C:
		case <-ready.C:
			t.Fatal("容量占用未到达")
		}
	}
	_, err = Call(context.Background(), endpoint, Request{Command: "status"})
	var transport *TransportError
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrProtocol) || !errors.As(err, &transport) || transport.Failure != FailureDisconnected {
		if transport != nil {
			t.Fatalf("容量拒绝误分类: 阶段=%s 类别=%s", transport.Phase, transport.Failure)
		}
		t.Fatalf("容量拒绝误分类: %T", err)
	}
	awaitSignal(t, capacity)
	if len(engine.State().Active) != 0 {
		t.Fatal("容量拒绝仍执行请求")
	}
	t.Logf("容量拒绝客户端阶段=%s 类别=%s；服务端类别=capacity", transport.Phase, transport.Failure)
}

func TestNativeUnixCallReturnsExactFrameFailureCategories(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		phase    TransportPhase
		failure  DiagnosticFailure
		protocol bool
	}{
		{"正常回复", frame([]byte(`{"version":1,"ok":true}`)), 0, 0, false},
		{"回复头截断", []byte{0, 0}, PhaseReadHeader, FailureTruncated, false},
		{"回复体截断", []byte{0, 0, 0, 8, '{'}, PhaseReadBody, FailureTruncated, false},
		{"完整畸形回复", frame([]byte(`{"version":1,"unexpected":"synthetic"}`)), 0, 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := temporaryEndpoint(t)
			engine, _, provider := fixture(t)
			server, err := Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider})
			must(t, err)
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := server.listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				var request Request
				if err = readFrame(conn, &request, maxRequestBytes); err == nil {
					_, err = conn.Write(test.packet)
				}
				done <- err
			}()
			response, err := Call(context.Background(), endpoint, Request{Command: "status"})
			must(t, <-done)
			if test.protocol {
				if !errors.Is(err, ErrProtocol) || errors.Is(err, ErrUnavailable) {
					t.Fatal("完整畸形回复误分类")
				}
				return
			}
			if test.failure != FailureNone {
				requireTransport(t, err, test.phase, test.failure)
				return
			}
			if err != nil || !response.OK {
				t.Fatal("正常回复没有成功")
			}
		})
	}
}

// 只查看固定原生 errno 类别，不输出系统错误中的端点路径或文本。
func TestNativeUnixCapacityNativeFailureEvidence(t *testing.T) {
	endpoint := temporaryEndpoint(t)
	engine, _, provider := fixture(t)
	server, err := Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider, Timeout: time.Second, MaxConnections: 1})
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() { cancel(); must(t, <-done); must(t, server.Close()) }()
	held, err := net.Dial("unix", filepath.Join(endpoint.Directory, socketName))
	must(t, err)
	defer held.Close()
	ready := time.NewTimer(time.Second)
	defer ready.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		server.connections.Lock()
		occupied := len(server.open) == 1
		server.connections.Unlock()
		if occupied {
			break
		}
		select {
		case <-tick.C:
		case <-ready.C:
			t.Fatal("未占用容量")
		}
	}
	counts := map[string]int{}
	for range 20 {
		conn, err := net.Dial("unix", filepath.Join(endpoint.Directory, socketName))
		must(t, err)
		_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
		var packet bytes.Buffer
		must(t, writeFrame(&packet, Request{Version: Version, Command: "status"}, maxRequestBytes))
		// header/body 分开写，覆盖 Call/writeFrame 的关闭窗口。
		_, err = conn.Write(packet.Bytes()[:4])
		if err == nil {
			_, err = conn.Write(packet.Bytes()[4:])
		}
		if err == nil {
			var size [4]byte
			_, err = io.ReadFull(conn, size[:])
		}
		_ = conn.Close()
		category := "native_other"
		var native syscall.Errno
		if errors.As(err, &native) {
			switch native {
			case syscall.EPIPE:
				category = "native_epipe"
			case syscall.ECONNRESET:
				category = "native_econnreset"
			case syscall.ENOTCONN:
				category = "native_enotconn"
			}
		} else if errors.Is(err, io.EOF) {
			category = "native_eof"
		}
		counts[category]++
		if category == "native_other" || diagnosticFailure(err) != FailureDisconnected {
			t.Fatalf("容量关闭的原生分类未覆盖: 类别=%s 传输类别=%s", category, diagnosticFailure(err))
		}
	}
	for _, category := range []string{"native_epipe", "native_econnreset", "native_enotconn", "native_eof", "native_other"} {
		t.Logf("类别=%s 次数=%d", category, counts[category])
	}
}
