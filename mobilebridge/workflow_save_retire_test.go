package mobilebridge

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWorkflowSaveFailureInvalidatesImmediatelyAndRetiresOutsideLocks(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	store := &memorySealed{}
	v, e := d.OpenWorkflow("https://synthetic.example.invalid", "synthetic-state", nil, nil, store)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	plain, e := v.workflow.ExportProtectedState()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(plain)
	if e = v.save(plain); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.cancel = cancel
	v.mu.Lock()
	store.fail = true
	result := make(chan error, 1)
	go func() { result <- v.save(plain) }()
	select {
	case e = <-result:
		if e == nil {
			t.Fatal("failed save accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("save tried to drain while the business lock was held")
	}
	if ctx.Err() == nil || !v.saveFailed.Load() {
		t.Fatal("failed persistence did not cancel the operation")
	}
	v.mu.Unlock()
	if _, e = v.Execute(`{"version":1,"operation":"view","endpoint":"https://synthetic.example.invalid"}`); !errors.Is(e, errClosed) {
		t.Fatal("failed workflow still executed", e)
	}
	store.fail = false
	if v.save(plain) == nil {
		t.Fatal("failed workflow saved without reopening")
	}
}
