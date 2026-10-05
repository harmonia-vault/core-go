package windowsservice

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harmonia-vault/core-go/platform"
)

type environmentLease interface {
	platform.UserEnvironmentStore
	Close() error
}
type rpcServer struct {
	store       environmentLease
	stopping    atomic.Bool
	gate        sync.RWMutex
	connections sync.Map
	workers     sync.WaitGroup
}

// serve 的 native authorize 必须在读完请求后绑定最后消息的 impersonation token。
// 停止先拒绝新请求、关闭连接，再等待正在执行的环境操作；不清空已下发配置。
func (s *rpcServer) serve(ctx context.Context, listener net.Listener, authorize func(net.Conn) error, ready func()) error {
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.stopping.Store(true)
			_ = listener.Close()
			s.connections.Range(func(k, v any) bool { _ = k.(net.Conn).Close(); return true })
		case <-stopped:
		}
	}()
	if ready != nil {
		ready()
	}
	semaphore := make(chan struct{}, 16)
	var acceptError error
	for {
		conn, e := listener.Accept()
		if e != nil {
			acceptError = e
			break
		}
		if s.stopping.Load() {
			_ = conn.Close()
			continue
		}
		select {
		case semaphore <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		s.connections.Store(conn, true)
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			defer func() { <-semaphore }()
			defer s.connections.Delete(conn)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			data, e := readFrame(conn)
			if e != nil {
				return
			}
			if authorize(conn) != nil {
				return
			}
			r, e := decodeRequest(data)
			if e != nil {
				return
			}
			s.gate.RLock()
			defer s.gate.RUnlock()
			if s.stopping.Load() {
				return
			}
			out := execute(s.store, r)
			encoded, e := json.Marshal(out)
			if e == nil {
				_ = writeFrame(conn, encoded)
			}
		}()
	}
	s.stopping.Store(true)
	_ = listener.Close()
	s.connections.Range(func(k, v any) bool { _ = k.(net.Conn).Close(); return true })
	s.workers.Wait()
	s.gate.Lock()
	e := s.store.Close()
	s.gate.Unlock()
	close(stopped)
	if e != nil {
		return ErrCleanup
	}
	if ctx.Err() != nil {
		return nil
	}
	if acceptError != nil {
		return ErrUnavailable
	}
	return nil
}
