package windowsservice

import (
	"context"
	"github.com/harmonia-vault/core-go/platform"
	"net"
	"sync"
	"testing"
	"time"
)

type blockedStore struct {
	mu      sync.Mutex
	enter   chan struct{}
	release chan struct{}
	writes  int
	closed  bool
}

func (s *blockedStore) UserSID() string { return testConfig().TargetSID }
func (s *blockedStore) Read(string) (platform.RegistryValue, bool, error) {
	return platform.RegistryValue{}, false, nil
}
func (s *blockedStore) Set(string, platform.RegistryValue) error {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	close(s.enter)
	<-s.release
	return nil
}
func (s *blockedStore) Delete(string) error { return nil }
func (s *blockedStore) Notify() error       { return nil }
func (s *blockedStore) Close() error        { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true; return nil }
func TestStopWaitsForInflightMutation(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &blockedStore{enter: make(chan struct{}), release: make(chan struct{})}
	server := rpcServer{store: store}
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, listener, func(net.Conn) error { return nil }, nil) }()
	conn, e := net.Dial("tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	data, e := encodeRequest(request{Op: "set", Name: "HARMONIA_TEST_VALUE", Value: "synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	if writeFrame(conn, data) != nil {
		t.Fatal("request")
	}
	select {
	case <-store.enter:
	case <-time.After(time.Second):
		t.Fatal("not entered")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("stop closed an in-flight profile")
	default:
	}
	store.mu.Lock()
	closed := store.closed
	store.mu.Unlock()
	if closed {
		t.Fatal("profile closed during mutation")
	}
	close(store.release)
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("stop timeout")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.closed || store.writes != 1 {
		t.Fatal("unexpected stop state")
	}
}
func TestUnauthorizedClientCannotMutate(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &blockedStore{enter: make(chan struct{}), release: make(chan struct{})}
	server := rpcServer{store: store}
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, listener, func(net.Conn) error { return ErrIdentity }, nil) }()
	conn, e := net.Dial("tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	data, _ := encodeRequest(request{Op: "set", Name: "HARMONIA_TEST_VALUE", Value: "synthetic"})
	if writeFrame(conn, data) != nil {
		t.Fatal("request")
	}
	if _, e = readFrame(conn); e == nil {
		t.Fatal("untrusted reply")
	}
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("stop timeout")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.writes != 0 {
		t.Fatal("unauthorized registry mutation")
	}
}
