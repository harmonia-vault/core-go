package appsecurity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"sync"
	"time"
)

// Native's Store must authenticate and bound this metadata with its independent
// integrity key. Neither a software MAC nor AtomicFile proves root-level
// resistance to restoring a complete old filesystem snapshot.
type AttemptState struct {
	Revision       uint64 `json:"revision"`
	RecordHash     string `json:"recordHash"`
	Total          uint64 `json:"total"`
	Failures       uint64 `json:"failures"`
	PendingAttempt string `json:"pendingAttempt,omitempty"`
	DelaySeconds   uint32 `json:"delaySeconds"`
}

// DurableStore is native-only. Load must reject missing/tampered metadata.
// Commit requires an exclusive cross-process slot lock/CAS, authenticated
// record, atomic write, fd.sync and exact readback before returning nil.
// An error may have committed; caller retires this Provider, never assumes it
// can roll back native storage or issue a lease from an uncertain commit.
type DurableStore interface {
	Acquire() error
	Release() error
	Load() (AttemptState, error)
	Commit(expectedRevision uint64, next AttemptState) error
}

func delay(failures uint64) uint32 {
	if failures < 5 {
		return 0
	}
	if failures >= 10 {
		return 600
	}
	d := uint32(30) << uint(failures-5)
	if d > 600 {
		return 600
	}
	return d
}
func (s AttemptState) valid(hash string) bool {
	return s.Revision > 0 && s.RecordHash == hash && lowerHex(s.RecordHash, 32) && s.Failures <= s.Total && s.DelaySeconds == delay(s.Failures) && (s.PendingAttempt == "" || lowerHex(s.PendingAttempt, 32) && s.Failures > 0)
}

// Provider never creates missing attempt metadata. Initial state is published
// atomically with CreateRecord by native; deleting limiter cannot mean zero.
type Provider struct {
	mu           sync.Mutex
	record       Record
	binding      Binding
	store        DurableStore
	retire       func()
	instance     [32]byte
	state        AttemptState
	blockedUntil time.Time
	closed       bool
	active       *Lease
}

func NewProvider(r Record, expected Binding, store DurableStore, retireOwner func()) (p *Provider, err error) {
	defer func() {
		if err != nil && retireOwner != nil {
			retireOwner()
		}
	}()
	if store == nil || retireOwner == nil || r.Validate(expected) != nil {
		return nil, ErrConfiguration
	}
	if e := store.Acquire(); e != nil {
		if errors.Is(e, ErrBusy) {
			return nil, ErrBusy
		}
		return nil, ErrPersistence
	}
	defer func() {
		if e := store.Release(); e != nil {
			p = nil
			err = ErrPersistence
		}
	}()
	state, e := store.Load()
	if e != nil {
		return nil, ErrPersistence
	}
	if !state.valid(recordHash(r)) {
		return nil, ErrState
	}
	p = &Provider{record: r, binding: expected, store: store, retire: retireOwner, state: state}
	if _, e = rand.Read(p.instance[:]); e != nil {
		return nil, ErrConfiguration
	}
	if state.DelaySeconds > 0 {
		p.blockedUntil = time.Now().Add(time.Duration(state.DelaySeconds) * time.Second)
	}
	return p, nil
}
func (p *Provider) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	l := p.active
	p.mu.Unlock()
	if l != nil {
		l.Close()
	}
}
func (p *Provider) failClosed() { p.closed = true }

// Unlock precharges durably before expensive KDF or decryption. Correct PIN
// must settle durably before this method returns any native operation lease.
func (p *Provider) Unlock(ctx context.Context, pin []byte, operationHash string) (lease *Lease, err error) {
	if p == nil {
		return nil, ErrClosed
	}
	if !p.mu.TryLock() {
		p.retire()
		return nil, ErrBusy
	}
	held := false
	defer func() {
		if held {
			if e := p.store.Release(); e != nil {
				p.closed = true
				err = ErrPersistence
			}
		}
		if err == nil && ctx != nil {
			err = ctx.Err()
		}
		failed := lease
		if err != nil {
			lease = nil
		} else {
			failed = nil
		}
		p.mu.Unlock()
		if failed != nil {
			failed.close(false)
		}
		if err != nil {
			p.retire()
		}
	}()
	if p.closed {
		return nil, ErrClosed
	}
	if p.active != nil {
		return nil, ErrBusy
	}
	if ctx == nil || !validPIN(pin) || !lowerHex(operationHash, 32) {
		return nil, ErrConfiguration
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := p.store.Acquire(); e != nil {
		if errors.Is(e, ErrBusy) {
			return nil, ErrBusy
		}
		p.failClosed()
		return nil, ErrPersistence
	}
	held = true
	fresh, e := p.store.Load()
	if e != nil {
		p.failClosed()
		return nil, ErrPersistence
	}
	if !fresh.valid(recordHash(p.record)) || fresh.Revision < p.state.Revision || fresh.Total < p.state.Total || fresh.Revision == p.state.Revision && fresh != p.state {
		p.failClosed()
		return nil, ErrState
	}
	if fresh.Revision != p.state.Revision {
		p.state = fresh
		if fresh.DelaySeconds > 0 {
			p.blockedUntil = time.Now().Add(time.Duration(fresh.DelaySeconds) * time.Second)
		}
	}
	if time.Now().Before(p.blockedUntil) {
		return nil, ErrLocked
	}
	if fresh.Total == math.MaxUint64 || fresh.Revision >= math.MaxUint64-1 || fresh.Failures == math.MaxUint64 {
		p.failClosed()
		return nil, ErrState
	}
	nonce, e := random(32)
	if e != nil {
		return nil, e
	}
	next := fresh
	next.Revision++
	next.Total++
	next.Failures++
	next.PendingAttempt = hex.EncodeToString(nonce)
	next.DelaySeconds = delay(next.Failures)
	if e = p.store.Commit(fresh.Revision, next); e != nil {
		p.failClosed()
		return nil, ErrPersistence
	}
	p.state = next
	if next.DelaySeconds > 0 {
		p.blockedUntil = time.Now().Add(time.Duration(next.DelaySeconds) * time.Second)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	material, e := openRecord(pin, p.record)
	if e != nil {
		return nil, e
	}
	defer func() {
		if material != nil {
			clear(material)
		}
	}()
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	settled := next
	settled.Revision++
	settled.Failures = 0
	settled.PendingAttempt = ""
	settled.DelaySeconds = 0
	if e = p.store.Commit(next.Revision, settled); e != nil {
		p.failClosed()
		return nil, ErrPersistence
	}
	p.state = settled
	p.blockedUntil = time.Time{}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	lease, e = newLease(p, ctx, operationHash, material)
	if e != nil {
		return nil, e
	}
	material = nil
	p.active = lease
	return lease, nil
}
