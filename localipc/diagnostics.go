package localipc

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

// DiagnosticStage 仅固定执行阶段，不包含命令、账号、路径或变量。
type DiagnosticStage uint8

const (
	StageAdmission DiagnosticStage = iota
	StageIdentity
	StageRequestRead
	StageQueue
	StageResponseHeader
	StageResponseBody
)

func (s DiagnosticStage) String() string {
	switch s {
	case StageAdmission:
		return "admission"
	case StageIdentity:
		return "identity"
	case StageRequestRead:
		return "request_read"
	case StageQueue:
		return "queue"
	case StageResponseHeader:
		return "response_header_write"
	case StageResponseBody:
		return "response_body_write"
	default:
		return "unknown"
	}
}

type DiagnosticFailure uint8

const (
	FailureNone DiagnosticFailure = iota
	FailureTimeout
	FailureDisconnected
	FailureTruncated
	FailureProtocol
	FailureIdentity
	FailureCapacity
	FailureCanceled
	FailureIO
)

func (f DiagnosticFailure) String() string {
	switch f {
	case FailureNone:
		return "none"
	case FailureTimeout:
		return "timeout"
	case FailureDisconnected:
		return "disconnected"
	case FailureTruncated:
		return "truncated"
	case FailureProtocol:
		return "protocol"
	case FailureIdentity:
		return "identity"
	case FailureCapacity:
		return "capacity"
	case FailureCanceled:
		return "canceled"
	default:
		return "io"
	}
}

// Diagnostic 只有类别与相对耗时。默认不启用、不记录日志；Observe回调必须快速
// 返回且自行同步。Queue事件表示完整帧已读取、即将等操作锁；其余为连接结束事件。
type Diagnostic struct {
	Stage            DiagnosticStage
	Failure          DiagnosticFailure
	QueueWait        time.Duration
	Execution        time.Duration
	Elapsed          time.Duration
	Budget           time.Duration
	ResponseOK       bool
	ExecutionStarted bool
	started          time.Time
}

func (s *Server) observe(d Diagnostic) {
	if s.config.Observe != nil {
		d.Elapsed = time.Since(d.started)
		d.started = time.Time{}
		s.config.Observe(d)
	}
}
func diagnosticFailure(err error) DiagnosticFailure {
	if err == nil {
		return FailureNone
	}
	var transport *TransportError
	if errors.As(err, &transport) {
		return transport.Failure
	}
	if errors.Is(err, ErrIdentity) {
		return FailureIdentity
	}
	if errors.Is(err, ErrProtocol) {
		return FailureProtocol
	}
	if errors.Is(err, context.Canceled) {
		return FailureCanceled
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return FailureTimeout
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return FailureTruncated
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ENOTCONN) {
		return FailureDisconnected
	}
	return FailureIO
}
