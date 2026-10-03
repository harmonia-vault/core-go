package mobileworkflow

import (
	"context"
	"errors"
	"github.com/harmonia-vault/core-go/syncclient"
	"os"
	"testing"
	"time"
)

// Callback-lifecycle component only; b1Session is explicitly a metadata fixture.
// Actual authorization is covered separately by the three HTTPS transactions.
type b3PortStore struct {
	loadError, saveError error
	entered, resume      chan struct{}
}

func (s *b3PortStore) LoadRecoveredPreparation() (syncclient.DAGRecoveredPreparation, error) {
	return syncclient.DAGRecoveredPreparation{}, s.loadError
}
func (s *b3PortStore) SaveRecoveredPreparation(syncclient.DAGRecoveredPreparation) error {
	if s.entered != nil {
		close(s.entered)
		<-s.resume
	}
	return s.saveError
}
func TestMobileDAGRecoveredPortFailureRetiresImmediately(t *testing.T) {
	for _, op := range []string{"load", "save"} {
		t.Run(op, func(t *testing.T) {
			_, w, _, r, e, session, _, scope := b1OwnerFixture(t)
			_, ctx, err := r.acquire(context.Background(), scope, false)
			if err != nil {
				t.Fatal(err)
			}
			j, err := w.newRecoveryDAGJournal()
			if err != nil {
				t.Fatal(err)
			}
			fault := errors.New("synthetic recovered preparation persistence failure")
			store := &b3PortStore{loadError: fault, saveError: fault}
			target := &dagOwnerTarget{entry: e, ctx: ctx, journal: j, recoveredPreparation: store}
			if err = e.port.attach(target); err != nil {
				t.Fatal(err)
			}
			if op == "load" {
				_, err = e.port.LoadRecoveredPreparation()
			} else {
				err = e.port.SaveRecoveredPreparation(syncclient.DAGRecoveredPreparation{})
			}
			if !errors.Is(err, fault) || !e.retired.Load() || ctx.Err() == nil || session.closed.Load() != 0 {
				t.Fatal("callback failure did not invalidate before close", err)
			}
			if err = e.port.detach(target); err != nil {
				t.Fatal(err)
			}
			if err = r.finish(e, ctx, fault); err == nil || session.closed.Load() != 1 {
				t.Fatal("finish did not close once", err)
			}
			r.Close()
			if session.closed.Load() != 1 {
				t.Fatal("closed twice")
			}
		})
	}
}
func TestMobileDAGRecoveredPortDrainAndAbsent(t *testing.T) {
	_, w, _, r, e, session, _, scope := b1OwnerFixture(t)
	_, ctx, err := r.acquire(context.Background(), scope, false)
	if err != nil {
		t.Fatal(err)
	}
	j, err := w.newRecoveryDAGJournal()
	if err != nil {
		t.Fatal(err)
	}
	store := &b3PortStore{loadError: os.ErrNotExist, entered: make(chan struct{}), resume: make(chan struct{})}
	target := &dagOwnerTarget{entry: e, ctx: ctx, journal: j, recoveredPreparation: store}
	if err = e.port.attach(target); err != nil {
		t.Fatal(err)
	}
	if _, err = e.port.LoadRecoveredPreparation(); !errors.Is(err, os.ErrNotExist) || e.retired.Load() {
		t.Fatal("absent preparation retired valid owner", err)
	}
	saved := make(chan error, 1)
	go func() { saved <- e.port.SaveRecoveredPreparation(syncclient.DAGRecoveredPreparation{}) }()
	<-store.entered
	r.Clear()
	if ctx.Err() == nil || !e.retired.Load() || session.closed.Load() != 0 {
		t.Fatal("clear must cancel before drain")
	}
	drained := make(chan error, 1)
	go func() { drained <- e.port.detach(target) }()
	select {
	case <-drained:
		t.Fatal("detach returned before callback drained")
	case <-time.After(10 * time.Millisecond):
	}
	close(store.resume)
	if err = <-saved; err != nil {
		t.Fatal(err)
	}
	if err = <-drained; err != nil {
		t.Fatal(err)
	}
	if err = r.finish(e, ctx, nil); err == nil || session.closed.Load() != 1 || e.port.target != nil {
		t.Fatal("drained cancel succeeded or wrong close count", err)
	}
}
