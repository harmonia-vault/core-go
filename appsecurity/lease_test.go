package appsecurity

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func leaseFixture(t *testing.T) (*Provider, *Lease, Binding, []byte, *diskStore) {
	t.Helper()
	r, s, b, material := fixture(t)
	store := newDiskStore(t, s)
	p, e := NewProvider(r, b, store, func() {})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.Close)
	l, e := p.Unlock(context.Background(), []byte("12345678"), strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(l.Close)
	return p, l, b, material, store
}
func TestPINLeaseOpaqueSingleUseAndBorrowedBufferCleared(t *testing.T) {
	_, l, b, material, store := leaseFixture(t)
	for _, v := range []any{l, *l} {
		if _, e := json.Marshal(v); !errors.Is(e, ErrNativeOnly) {
			t.Fatal("lease serialized", e)
		}
		var out bytes.Buffer
		if e := gob.NewEncoder(&out).Encode(v); e == nil {
			t.Fatal("lease gob serialized")
		}
		if fmt.Sprintf("%#v", v) != "native local PIN lease (opaque)" {
			t.Fatal("lease formatting exposed state")
		}
	}
	var borrowed []byte
	if e := l.Consume(context.Background(), b, strings.Repeat("a", 64), func(_ context.Context, m []byte) error {
		if !bytes.Equal(m, material) {
			t.Fatal("native callback received wrong material")
		}
		borrowed = m
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	for _, v := range borrowed {
		if v != 0 {
			t.Fatal("borrowed material not cleared")
		}
	}
	if e := l.Consume(context.Background(), b, strings.Repeat("a", 64), func(context.Context, []byte) error { t.Fatal("reused lease ran"); return nil }); !errors.Is(e, ErrLease) {
		t.Fatal(e)
	}
	state, e := store.Load()
	if e != nil || state.Total != 1 || state.Failures != 0 || state.PendingAttempt != "" {
		t.Fatal("successful decrypt did not settle before lease", e)
	}
}
func TestPINLeaseRejectsScopeAndCompetingConsumers(t *testing.T) {
	t.Run("scope", func(t *testing.T) {
		_, l, b, _, _ := leaseFixture(t)
		b.KeyEpoch = strings.Repeat("4", 32)
		if e := l.Consume(context.Background(), b, strings.Repeat("a", 64), func(context.Context, []byte) error { t.Fatal("changed generation/scope ran"); return nil }); !errors.Is(e, ErrLease) {
			t.Fatal(e)
		}
	})
	t.Run("one-consumer", func(t *testing.T) {
		_, l, b, _, _ := leaseFixture(t)
		var calls atomic.Int32
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- l.Consume(context.Background(), b, strings.Repeat("a", 64), func(context.Context, []byte) error { calls.Add(1); return nil })
			}()
		}
		wg.Wait()
		close(errs)
		success := 0
		for e := range errs {
			if e == nil {
				success++
			} else if !errors.Is(e, ErrLease) && !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
		}
		if success > 1 || calls.Load() != 1 {
			t.Fatal("lease nonce authorized twice")
		}
	})
}
func TestPINReleaseFailureAndCancellationCannotReturnGrant(t *testing.T) {
	r, s, b, _ := fixture(t)
	store := newDiskStore(t, s)
	var retired atomic.Int32
	p, e := NewProvider(r, b, store, func() { retired.Add(1) })
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	store.failRelease = true
	if l, e := p.Unlock(context.Background(), []byte("12345678"), strings.Repeat("a", 64)); !errors.Is(e, ErrPersistence) || l != nil || retired.Load() == 0 {
		t.Fatal("failed native unlock issued grant", e)
	}
}

func TestPINLeaseCanceledNativeCallbackCannotReportSuccess(t *testing.T) {
	_, l, b, _, _ := leaseFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var material []byte
	err := l.Consume(ctx, b, strings.Repeat("a", 64), func(_ context.Context, m []byte) error { material = m; cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("canceled native callback reported success", err)
	}
	for _, v := range material {
		if v != 0 {
			t.Fatal("canceled callback retained borrowed material")
		}
	}
}

func TestPINLeaseKeepsOriginalUnlockContextAuthoritative(t *testing.T) {
	r, state, binding, _ := fixture(t)
	store := newDiskStore(t, state)
	var retired atomic.Int32
	p, err := NewProvider(r, binding, store, func() { retired.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	original, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := p.Unlock(original, []byte("12345678"), strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// Consume cannot replace the authenticated operation's original context.
	err = l.Consume(context.Background(), binding, strings.Repeat("a", 64), func(context.Context, []byte) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) || retired.Load() == 0 {
		t.Fatal("original cancellation lost through replacement context", err)
	}
}
