package localipc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireTransport(t *testing.T, err error, phase TransportPhase, failure DiagnosticFailure) {
	t.Helper()
	var transport *TransportError
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrProtocol) || !errors.As(err, &transport) || transport.Phase != phase || transport.Failure != failure {
		t.Fatalf("传输分类错误: 类型=%T", err)
	}
}
func TestTransportDistinguishesClosedTruncatedTimeoutAndProtocol(t *testing.T) {
	for _, test := range []struct {
		packet  []byte
		phase   TransportPhase
		failure DiagnosticFailure
	}{
		{nil, PhaseReadHeader, FailureDisconnected},
		{[]byte{0, 0}, PhaseReadHeader, FailureTruncated},
		{[]byte{0, 0, 0, 8}, PhaseReadBody, FailureTruncated},
		{[]byte{0, 0, 0, 8, '{'}, PhaseReadBody, FailureTruncated},
	} {
		var request Request
		requireTransport(t, readFrame(bytes.NewReader(test.packet), &request, maxRequestBytes), test.phase, test.failure)
	}
	for _, packet := range [][]byte{{0, 0, 0, 0}, {255, 255, 255, 255}, frame([]byte(`{`)), frame([]byte(`{"version":1,"command":"status","unknown":"synthetic"}`)), frame([]byte(`{"version":1} {}`))} {
		var request Request
		if err := readFrame(bytes.NewReader(packet), &request, maxRequestBytes); !errors.Is(err, ErrProtocol) || errors.Is(err, ErrUnavailable) {
			t.Fatal("完整畸形帧被误报为传输中断")
		}
	}
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	must(t, reader.SetDeadline(time.Now().Add(20*time.Millisecond)))
	var request Request
	requireTransport(t, readFrame(reader, &request, maxRequestBytes), PhaseReadHeader, FailureTimeout)
	must(t, writer.SetDeadline(time.Now().Add(20*time.Millisecond)))
	requireTransport(t, writeFrame(writer, Request{Version: Version, Command: "status"}, maxRequestBytes), PhaseWriteHeader, FailureTimeout)
}

type syntheticFailWriter struct {
	writes int
	failAt int
}

func (w *syntheticFailWriter) Write(data []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, errors.New("SYNTHETIC_SECRET_VALUE_AND_PRIVATE_PATH")
	}
	return len(data), nil
}
func TestTransportErrorsAndDiagnosticsNeverRetainOriginalError(t *testing.T) {
	for _, test := range []struct {
		at    int
		phase TransportPhase
	}{{1, PhaseWriteHeader}, {2, PhaseWriteBody}} {
		err := writeFrame(&syntheticFailWriter{failAt: test.at}, Request{Version: Version, Command: "status"}, maxRequestBytes)
		requireTransport(t, err, test.phase, FailureIO)
		if strings.Contains(err.Error(), "SYNTHETIC") || strings.Contains(errors.Unwrap(err).Error(), "SYNTHETIC") || diagnosticFailure(err) != FailureIO {
			t.Fatal("错误持有原始文本")
		}
	}
	for _, native := range []error{syscall.EPIPE, syscall.ECONNRESET, syscall.ENOTCONN} {
		err := transportError(PhaseWriteHeader, &net.OpError{Op: "write", Net: "unix", Err: native})
		requireTransport(t, err, PhaseWriteHeader, FailureDisconnected)
	}
	if diagnosticFailure(io.ErrUnexpectedEOF) != FailureTruncated || diagnosticFailure(io.ErrClosedPipe) != FailureDisconnected {
		t.Fatal("固定截断/断开类别错误")
	}
	var observed Diagnostic
	server := &Server{config: Config{Observe: func(d Diagnostic) { observed = d }}}
	server.observe(Diagnostic{Stage: StageResponseHeader, Failure: FailureIO, started: time.Now()})
	if !observed.started.IsZero() || observed.Stage.String() != "response_header_write" || observed.Failure.String() != "io" {
		t.Fatal("观察器暴露起始时间或错误类别不固定")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireTransport(t, callTransportError(ctx, transportError(PhaseReadHeader, net.ErrClosed)), PhaseReadHeader, FailureCanceled)
	if !errors.Is(callTransportError(ctx, ErrProtocol), ErrProtocol) {
		t.Fatal("取消掩盖真实协议错误")
	}
}
