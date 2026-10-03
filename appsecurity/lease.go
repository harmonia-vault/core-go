package appsecurity

import (
	"context"
	"crypto/rand"
	"sync"
	"time"
)

const leaseTTL = 30 * time.Second

// Lease is a native-only, one-operation resource, not account/device trust.
// The wrapper contains no secret buffers or mutex, so both copied values and
// pointers have safe formatting and reject serialization.
type Lease struct{ state *leaseState }
type leaseState struct {
	mu            sync.Mutex
	provider      *Provider
	instance      [32]byte
	binding       Binding
	operationHash string
	nonce         [32]byte
	material      []byte
	deadline      time.Time
	originalCtx   context.Context
	used, closed  bool
	timer         *time.Timer
	cancel        context.CancelFunc
	done          chan struct{}
}

func (Lease) String() string               { return "native local PIN lease (opaque)" }
func (Lease) GoString() string             { return "native local PIN lease (opaque)" }
func (Lease) MarshalText() ([]byte, error) { return nil, ErrNativeOnly }
func (Lease) MarshalJSON() ([]byte, error) { return nil, ErrNativeOnly }
func (Lease) GobEncode() ([]byte, error)   { return nil, ErrNativeOnly }
func (*Lease) GobDecode([]byte) error      { return ErrNativeOnly }
func (*Lease) UnmarshalText([]byte) error  { return ErrNativeOnly }
func (*Lease) UnmarshalJSON([]byte) error  { return ErrNativeOnly }
func newLease(p *Provider, ctx context.Context, operationHash string, material []byte) (*Lease, error) {
	deadline := time.Now().Add(leaseTTL)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if !deadline.After(time.Now()) {
		return nil, context.DeadlineExceeded
	}
	s := &leaseState{provider: p, instance: p.instance, binding: p.binding, operationHash: operationHash, material: material, deadline: deadline, originalCtx: ctx, done: make(chan struct{})}
	if _, e := rand.Read(s.nonce[:]); e != nil {
		return nil, ErrConfiguration
	}
	l := &Lease{state: s}
	// Timer/context can close a nearly expired lease immediately. Initialize
	// timer under its mutex before either callback reads it.
	s.mu.Lock()
	s.timer = time.AfterFunc(time.Until(deadline), func() { l.close(true) })
	s.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
			l.close(true)
		case <-s.done:
		}
	}()
	return l, nil
}
func (l *Lease) Close() { l.close(true) }
func (l *Lease) close(retire bool) {
	if l == nil || l.state == nil {
		return
	}
	s := l.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	clear(s.material)
	s.material = nil
	clear(s.nonce[:])
	if s.timer != nil {
		s.timer.Stop()
	}
	if s.cancel != nil {
		s.cancel()
	}
	close(s.done)
	p := s.provider
	s.mu.Unlock()
	if p != nil {
		p.mu.Lock()
		if p.active == l {
			p.active = nil
		}
		p.mu.Unlock()
		if retire {
			p.retire()
		}
	}
}

// Consume lends material only to a synchronous trusted native callback which
// imports/closes the Go device; it must not retain/export the buffer. The
// callback is deliberately not gomobile-bindable. It is not exposed to Dart.
// The context's operation timeout remains authoritative after consumption.
func (l *Lease) Consume(ctx context.Context, expected Binding, operationHash string, operation func(context.Context, []byte) error) (err error) {
	if l == nil || l.state == nil {
		return ErrLease
	}
	s := l.state
	defer func() {
		if err != nil && s.provider != nil {
			s.provider.retire()
		}
	}()
	if ctx == nil || operation == nil {
		l.close(true)
		return ErrLease
	}
	s.mu.Lock()
	if s.closed || s.used || s.binding != expected || s.operationHash != operationHash || !time.Now().Before(s.deadline) {
		s.mu.Unlock()
		l.close(true)
		return ErrLease
	}
	if e := s.originalCtx.Err(); e != nil {
		s.mu.Unlock()
		l.close(true)
		return e
	}
	if e := ctx.Err(); e != nil {
		s.mu.Unlock()
		l.close(true)
		return e
	}
	p := s.provider
	p.mu.Lock()
	valid := !p.closed && p.active == l && p.instance == s.instance
	p.mu.Unlock()
	if !valid {
		s.mu.Unlock()
		l.close(true)
		return ErrLease
	}
	s.used = true
	material := s.material
	s.material = nil
	if s.timer != nil {
		s.timer.Stop()
	}
	operationCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	stopOriginal := context.AfterFunc(s.originalCtx, cancel)
	s.mu.Unlock()
	defer func() { stopOriginal(); cancel(); clear(material); l.close(err != nil) }()
	err = operation(operationCtx, material)
	if err == nil {
		err = s.originalCtx.Err()
	}
	if err == nil {
		err = operationCtx.Err()
	}
	return err
}
