// Package localipc 为单一后台 Engine 提供按系统本地身份隔离的白名单接口。
// 不接收云快照、密钥、签授权或账号信任数据；它不是入网或网络同步入口。
package localipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/harmonia-vault/core-go/localstate"
)

const (
	Version          = 1
	maxRequestBytes  = 512 << 10
	maxResponseBytes = 8 << 20
)

var (
	ErrIdentity    = errors.New("IPC local identity mismatch")
	ErrProtocol    = errors.New("invalid IPC protocol")
	ErrUnavailable = errors.New("IPC endpoint unavailable")
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	namePattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// Endpoint 的 Unix UserID 为十进制 uid；Windows 为目标用户 SID，并须明确
// ServiceSID。Directory 为服务私有目录，不接受任意网络 socket/pipe 地址。
type Endpoint struct {
	Directory  string
	UserID     string
	ServiceSID string
}
type Request struct {
	Version       int               `json:"version"`
	Command       string            `json:"command"`
	EnvironmentID string            `json:"environmentId,omitempty"`
	Name          string            `json:"name,omitempty"`
	Value         *string           `json:"value,omitempty"`
	Priority      *int              `json:"priority,omitempty"`
	RequestID     string            `json:"requestId,omitempty"`
	Selected      map[string]string `json:"selected,omitempty"`
}
type Status struct {
	Paused            bool                    `json:"paused"`
	AccountGeneration uint64                  `json:"accountGeneration"`
	Sequence          uint64                  `json:"sequence"`
	Environments      int                     `json:"environments"`
	Active            []localstate.Activation `json:"active"`
	TrackedOriginals  int                     `json:"trackedOriginals"`
}
type Response struct {
	Version int                `json:"version"`
	OK      bool               `json:"ok"`
	Code    string             `json:"code,omitempty"`
	Status  *Status            `json:"status,omitempty"`
	Values  map[string]string  `json:"values,omitempty"`
	Write   *SharedWriteResult `json:"write,omitempty"`
}
type Config struct {
	Endpoint       Endpoint
	Engine         *localstate.Engine
	Provider       localstate.Provider
	Now            func() time.Time
	Timeout        time.Duration
	MaxConnections int
	// Observe 默认关闭，只接收固定类别和耗时，不记录请求或原错误。
	Observe func(Diagnostic)
	// OnLogout 由后台 owner 停止旧同步并清除本地设备/会话资料；IPC 不持有 Vault。
	OnLogout    func(context.Context) error
	OnlineWrite func(context.Context, SharedWriteRequest) (SharedWriteResult, error)
}

// nativeHandleConn 串行化原生句柄身份查询与 Close，避免查询过程中句柄被释放。
type nativeHandleConn struct {
	net.Conn
	native sync.Mutex
}

func (c *nativeHandleConn) Close() error {
	c.native.Lock()
	defer c.native.Unlock()
	return c.Conn.Close()
}
func useNative(conn net.Conn, fn func(net.Conn) error) error {
	if owned, ok := conn.(*nativeHandleConn); ok {
		owned.native.Lock()
		defer owned.native.Unlock()
		return fn(owned.Conn)
	}
	return fn(conn)
}

type nativeListener struct {
	net.Listener
	cleanup func() error
}
type Server struct {
	config       Config
	listener     nativeListener
	operations   operationGate
	connections  sync.Mutex
	open         map[net.Conn]bool
	closing      bool
	workers      sync.WaitGroup
	stopOnce     sync.Once
	cleanupOnce  sync.Once
	cleanupError error
}

// Listen 不打开第二个状态文件；后台调用方应持有唯一 Store 的生命周期锁。
// 用户退出 CLI 仅关闭其连接，后台服务的上下文由服务管理器掌握。
func Listen(config Config) (*Server, error) {
	if config.Engine == nil || config.Provider == nil {
		return nil, errors.New("IPC requires a background engine and isolated provider")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.Timeout < time.Millisecond || config.Timeout > time.Minute {
		return nil, ErrProtocol
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 16
	}
	if config.MaxConnections < 1 || config.MaxConnections > 64 {
		return nil, ErrProtocol
	}
	listener, err := listenNative(config.Endpoint)
	if err != nil {
		return nil, err
	}
	return &Server{config: config, listener: listener, open: map[net.Conn]bool{}}, nil
}
func (s *Server) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, s.stopTransport)
	defer stop()
	defer s.Close()
	slots := make(chan struct{}, s.config.MaxConnections)
	for {
		rawConn, err := s.listener.Accept()
		if err != nil {
			s.workers.Wait()
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return ErrUnavailable
		}
		conn := &nativeHandleConn{Conn: rawConn}
		select {
		case slots <- struct{}{}:
		default:
			s.observe(Diagnostic{Stage: StageAdmission, Failure: FailureCapacity, Budget: s.config.Timeout, started: time.Now()})
			_ = conn.Close()
			continue
		}
		s.connections.Lock()
		if s.closing {
			s.connections.Unlock()
			<-slots
			_ = conn.Close()
			continue
		}
		s.open[conn] = true
		s.workers.Add(1)
		s.connections.Unlock()
		go func() {
			diagnostic := Diagnostic{Stage: StageIdentity, Budget: s.config.Timeout, started: time.Now()}
			defer s.workers.Done()
			defer func() { <-slots; s.connections.Lock(); delete(s.open, conn); s.connections.Unlock(); _ = conn.Close() }()
			defer func() { s.observe(diagnostic) }()
			deadline := time.Now().Add(s.config.Timeout)
			_ = conn.SetDeadline(deadline)
			if err := authorizeNative(conn, s.config.Endpoint, false); err != nil {
				diagnostic.Failure = diagnosticFailure(err)
				return
			}
			diagnostic.Stage = StageRequestRead
			var request Request
			if err := readFrame(conn, &request, maxRequestBytes); err != nil {
				diagnostic.Failure = diagnosticFailure(err)
				_ = writeFrame(conn, Response{Version: Version, Code: "invalid_request"}, maxResponseBytes)
				return
			}
			if isSharedWrite(request.Command) {
				diagnostic.Budget = time.Minute
				deadline = time.Now().Add(time.Minute)
				_ = conn.SetDeadline(deadline)
			}
			requestCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			response := s.dispatchObserved(requestCtx, request, &diagnostic)
			diagnostic.ResponseOK = response.OK
			if err := writeFrameObserved(conn, response, maxResponseBytes, &diagnostic); err != nil {
				diagnostic.Failure = diagnosticFailure(err)
			}
		}()
	}
}
func (s *Server) stopTransport() {
	s.stopOnce.Do(func() {
		_ = s.listener.Close()
		s.connections.Lock()
		defer s.connections.Unlock()
		s.closing = true
		for conn := range s.open {
			_ = conn.Close()
		}
	})
}
func (s *Server) Close() error {
	s.stopTransport()
	s.workers.Wait()
	s.cleanupOnce.Do(func() {
		if s.listener.cleanup != nil {
			s.cleanupError = s.listener.cleanup()
		}
	})
	return s.cleanupError
}

// Reconcile 与命令共用串行操作锁，供后台定时器与已验证撤销处理调用。
func (s *Server) Reconcile(ctx context.Context, now time.Time) error {
	if err := s.operations.Lock(ctx); err != nil {
		return err
	}
	defer s.operations.Unlock()
	return s.config.Engine.Reconcile(ctx, s.config.Provider, now)
}
func validateRequest(r Request) error {
	if isSharedWrite(r.Command) {
		return validateSharedRequest(r)
	}
	if r.RequestID != "" || len(r.Selected) != 0 {
		return ErrProtocol
	}
	if r.Version != Version {
		return ErrProtocol
	}
	envValid := idPattern.MatchString(r.EnvironmentID)
	nameValid := namePattern.MatchString(r.Name) && !strings.HasPrefix(strings.ToUpper(r.Name), "__HARMONIA_")
	switch r.Command {
	case "status", "export", "pause", "resume", "logout":
		if r.EnvironmentID != "" || r.Name != "" || r.Value != nil || r.Priority != nil {
			return ErrProtocol
		}
	case "activate":
		if !envValid || r.Name != "" || r.Value != nil {
			return ErrProtocol
		}
	case "priority":
		if !envValid || r.Name != "" || r.Value != nil || r.Priority == nil {
			return ErrProtocol
		}
	case "deactivate":
		if !envValid || r.Name != "" || r.Value != nil || r.Priority != nil {
			return ErrProtocol
		}
	case "override-set":
		if !envValid || !nameValid || r.Value == nil || r.Priority != nil || len(*r.Value) > 65536 || strings.ContainsRune(*r.Value, 0) {
			return ErrProtocol
		}
	case "override-remove":
		if !envValid || !nameValid || r.Value != nil || r.Priority != nil {
			return ErrProtocol
		}
	default:
		return ErrProtocol
	}
	return nil
}
func (s *Server) dispatch(ctx context.Context, r Request) Response {
	return s.dispatchObserved(ctx, r, nil)
}
func (s *Server) dispatchObserved(ctx context.Context, r Request, diagnostic *Diagnostic) Response {
	response := Response{Version: Version}
	if validateRequest(r) != nil {
		response.Code = "invalid_command"
		return response
	}
	queued := time.Now()
	if diagnostic != nil {
		event := *diagnostic
		event.Stage = StageQueue
		s.observe(event)
	}
	err := s.operations.Lock(ctx)
	if diagnostic != nil {
		diagnostic.QueueWait = time.Since(queued)
	}
	if err != nil {
		response.Code = "request_canceled"
		if errors.Is(err, context.DeadlineExceeded) {
			response.Code = "request_expired"
		}
		if diagnostic != nil {
			diagnostic.Failure = diagnosticFailure(err)
		}
		return response
	}
	defer s.operations.Unlock()
	if diagnostic != nil {
		diagnostic.ExecutionStarted = true
		execution := time.Now()
		defer func() { diagnostic.Execution = time.Since(execution) }()
	}
	now := s.config.Now()
	engine := s.config.Engine
	if isSharedWrite(r.Command) {
		return s.dispatchShared(ctx, r, now)
	}
	switch r.Command {
	case "activate":
		priority := 0
		if r.Priority != nil {
			priority = *r.Priority
		}
		err = engine.Activate(r.EnvironmentID, priority, now)
	case "priority":
		found := false
		for _, a := range engine.State().Active {
			if a.EnvironmentID == r.EnvironmentID {
				found = true
				break
			}
		}
		if !found {
			response.Code = "inactive_environment"
			return response
		}
		err = engine.Activate(r.EnvironmentID, *r.Priority, now)
	case "deactivate":
		err = engine.Deactivate(r.EnvironmentID)
	case "override-set":
		err = engine.SetOverride(r.EnvironmentID, r.Name, *r.Value, now)
	case "override-remove":
		err = engine.RemoveOverride(r.EnvironmentID, r.Name)
	case "pause":
		err = engine.SetPaused(true)
	case "resume":
		err = engine.SetPaused(false)
	case "logout":
		err = engine.Logout()
	}
	if err != nil {
		if errors.Is(err, localstate.ErrUnauthorized) {
			response.Code = "unauthorized_environment"
		} else {
			response.Code = "command_failed"
		}
		return response
	}
	var cleanupError error
	if r.Command == "logout" && s.config.OnLogout != nil {
		cleanupError = s.config.OnLogout(ctx)
	}
	if err = engine.Reconcile(ctx, s.config.Provider, now); err != nil {
		response.Code = "provider_or_persistence_failed"
		return response
	}
	if cleanupError != nil {
		response.Code = "logout_credentials_cleanup_failed"
		return response
	}
	if r.Command == "export" {
		response.Values, err = engine.Effective(now)
		if err != nil {
			response.Code = "command_failed"
			return response
		}
	}
	state := engine.State()
	response.Status = &Status{Paused: state.Paused, AccountGeneration: state.Cloud.AccountGeneration, Sequence: state.Cloud.Sequence, Environments: len(state.Cloud.Environments), Active: state.Active, TrackedOriginals: len(state.Originals)}
	response.OK = true
	return response
}

// Call 每次只发送一个命令。断连后的结果可能已持久化；调用方可查询 status
// 并重试同一幂等本地操作，不应因没收到回复就假定后台没有执行。
func Call(ctx context.Context, endpoint Endpoint, request Request) (Response, error) {
	if request.Version == 0 {
		request.Version = Version
	}
	if validateRequest(request) != nil {
		return Response{}, ErrProtocol
	}
	rawConn, err := dialNative(ctx, endpoint)
	if err != nil {
		return Response{}, callTransportError(ctx, transportError(PhaseDial, err))
	}
	conn := &nativeHandleConn{Conn: rawConn}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	timeout := 5 * time.Second
	if isSharedWrite(request.Command) {
		timeout = time.Minute
	}
	deadline := time.Now().Add(timeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	_ = conn.SetDeadline(deadline)
	if authorizeNative(conn, endpoint, true) != nil {
		return Response{}, ErrIdentity
	}
	if err = writeFrame(conn, request, maxRequestBytes); err != nil {
		return Response{}, callTransportError(ctx, err)
	}
	var response Response
	if err = readFrame(conn, &response, maxResponseBytes); err != nil {
		return Response{}, callTransportError(ctx, err)
	}
	if response.Version != Version {
		return Response{}, ErrProtocol
	}
	return response, nil
}
func writeFrame(w io.Writer, value any, maximum uint32) error {
	return writeFrameObserved(w, value, maximum, nil)
}
func writeFrameObserved(w io.Writer, value any, maximum uint32, diagnostic *Diagnostic) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) == 0 || uint64(len(data)) > uint64(maximum) {
		return ErrProtocol
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data)))
	if diagnostic != nil {
		diagnostic.Stage = StageResponseHeader
	}
	if _, err = io.Copy(w, bytes.NewReader(size[:])); err != nil {
		return transportError(PhaseWriteHeader, err)
	}
	if diagnostic != nil {
		diagnostic.Stage = StageResponseBody
	}
	_, err = io.Copy(w, bytes.NewReader(data))
	return transportError(PhaseWriteBody, err)
}
func readFrame(r io.Reader, dst any, maximum uint32) error {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return transportError(PhaseReadHeader, err)
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maximum {
		return ErrProtocol
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return transportError(PhaseReadBody, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil {
		return ErrProtocol
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return ErrProtocol
	}
	return nil
}
