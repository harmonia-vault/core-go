package windowsservice

import (
	"testing"
	"time"
)

func TestFailedSelfTerminateKeepsPinsUntilDrain(t *testing.T) {
	done := make(chan error, 1)
	ticks := make(chan time.Time, 1)
	terminated := make(chan struct{}, 1)
	heartbeats := make(chan struct{}, 1)
	returned := make(chan error, 1)
	go func() {
		returned <- drainFailure(done, ticks, func() { terminated <- struct{}{} }, func() { heartbeats <- struct{}{} })
	}()
	<-terminated
	ticks <- time.Now()
	<-heartbeats
	select {
	case <-returned:
		t.Fatal("pins released while worker still alive")
	default:
	}
	done <- nil
	if err := <-returned; err != nil {
		t.Fatal(err)
	}
}
func TestCleanupFailureCannotReportStopped(t *testing.T) {
	done := make(chan error, 1)
	done <- ErrCleanup
	calls := 0
	recovered := make(chan any, 1)
	go func() {
		defer func() { recovered <- recover() }()
		_ = drainFailure(done, nil, func() {
			calls++
			if calls == 2 {
				panic("synthetic-self-termination")
			}
		}, func() {})
		recovered <- "unsafe return"
	}()
	if got := <-recovered; got != "synthetic-self-termination" {
		t.Fatalf("cleanup returned without process termination: %v", got)
	}
}
