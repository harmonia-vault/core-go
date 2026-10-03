package mobileworkflow

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestDAGOwnerPortSaveFailureInvalidatesBeforeRetire(t *testing.T) {
	_, _, j, p, slot := dagMobileFixture(t)
	if err := j.Save(p); err != nil {
		t.Fatal(err)
	}
	before := slot.read()
	slot.fail = true
	scope := DAGOwnerScope{Namespace: "synthetic", Slot: "failure"}
	r, _ := NewDAGRecoveryRegistry(scope)
	defer r.Close()
	e, ctx, err := r.acquire(context.Background(), scope, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &b1Session{port: &e.port}
	e.session = s
	target := &dagOwnerTarget{e, ctx, j}
	if err = e.port.attach(target); err != nil {
		t.Fatal(err)
	}
	p.Attempted = true
	if err = e.port.Save(p); !errors.Is(err, ErrDAGPersistence) {
		t.Fatal("failure hidden", err)
	}
	if !e.retired.Load() || ctx.Err() == nil || s.closed.Load() != 0 {
		t.Fatal("failed Save must immediately cancel without locked Close")
	}
	if !bytes.Equal(before, slot.read()) {
		t.Fatal("failed Save changed original")
	}
	if e.port.OwnerAlive() == nil {
		t.Fatal("retired lease still live")
	}
	if err = e.port.detach(target); err != nil {
		t.Fatal(err)
	}
	if r.finish(e, ctx, err) == nil || s.closed.Load() != 1 {
		t.Fatal("failed operation cleanup/success wrong")
	}
}
func TestDAGOwnerPortDetachDrainsAndCannotReattachOldTarget(t *testing.T) {
	_, _, j, p, slot := dagMobileFixture(t)
	if err := j.Save(p); err != nil {
		t.Fatal(err)
	}
	scope := DAGOwnerScope{Namespace: "synthetic", Slot: "drain"}
	r, _ := NewDAGRecoveryRegistry(scope)
	defer r.Close()
	e, ctx, err := r.acquire(context.Background(), scope, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &b1Session{port: &e.port}
	e.session = s
	target := &dagOwnerTarget{e, ctx, j}
	if err = e.port.attach(target); err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	slot.entered, slot.resume = entered, resume
	saved, detached := make(chan error, 1), make(chan error, 1)
	p.Attempted = true
	go func() { saved <- e.port.Save(p) }()
	<-entered
	go func() { detached <- e.port.detach(target) }()
	select {
	case <-detached:
		t.Fatal("detach bypassed active callback")
	case <-time.After(20 * time.Millisecond):
	}
	r.Clear()
	if ctx.Err() == nil || s.closed.Load() != 0 {
		t.Fatal("cancel blocked or Close before drain")
	}
	close(resume)
	if err = <-saved; err != nil {
		t.Fatal(err)
	}
	if err = <-detached; err != nil {
		t.Fatal(err)
	}
	if e.port.OwnerAlive() == nil {
		t.Fatal("detached port remained usable")
	}
	if e.port.attach(target) == nil {
		t.Fatal("retired target reattached")
	}
	if err = r.finish(e, ctx, nil); err == nil || s.closed.Load() != 1 {
		t.Fatal("canceled operation reported success")
	}
}
