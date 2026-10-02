package localipc

import (
	"context"
	"errors"
	"io"
)

// TransportPhase 仅描述帧传输阶段，不持有请求数据或操作系统错误。
type TransportPhase uint8

const (
	PhaseDial TransportPhase = iota
	PhaseReadHeader
	PhaseReadBody
	PhaseWriteHeader
	PhaseWriteBody
)

func (p TransportPhase) String() string {
	switch p {
	case PhaseDial:
		return "dial"
	case PhaseReadHeader:
		return "read_header"
	case PhaseReadBody:
		return "read_body"
	case PhaseWriteHeader:
		return "write_header"
	case PhaseWriteBody:
		return "write_body"
	default:
		return "io"
	}
}

// TransportError 是可识别的固定分类；不会包装原始路径、值或网络错误文本。
// errors.Is(err, ErrUnavailable) 表示没有完整回复，不能据此断言操作未执行。
type TransportError struct {
	Phase   TransportPhase
	Failure DiagnosticFailure
}

func (e *TransportError) Error() string {
	return "IPC transport " + e.Phase.String() + ": " + e.Failure.String()
}
func (e *TransportError) Unwrap() error { return ErrUnavailable }
func transportError(phase TransportPhase, err error) error {
	if err == nil {
		return nil
	}
	failure := diagnosticFailure(err)
	if phase == PhaseReadBody && errors.Is(err, io.EOF) {
		failure = FailureTruncated
	}
	return &TransportError{Phase: phase, Failure: failure}
}
func callTransportError(ctx context.Context, err error) error {
	var transport *TransportError
	if errors.As(err, &transport) && ctx.Err() != nil {
		return &TransportError{Phase: transport.Phase, Failure: diagnosticFailure(ctx.Err())}
	}
	return err
}
