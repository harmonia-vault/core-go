package syncclient

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestVerifiedPullCommitExactContextAndFailureBeforePOST(t *testing.T) {
	f := newWriteFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	callbackFailure := errors.New("synthetic verified commit failure")
	var calls atomic.Int32
	bound, e := f.client.WithVerifiedPullCommit(ctx, func(actual context.Context, p Pull) error {
		calls.Add(1)
		if actual != ctx || f.engine.State().Cloud.Sequence != p.Sequence {
			t.Error("callback before exact verified Engine acceptance")
		}
		return callbackFailure
	})
	check(t, e)
	// 相同context用于另一Client不会共享回调；普通nil行为保持。
	_, e = f.client.Pull(ctx)
	check(t, e)
	if calls.Load() != 0 {
		t.Fatal("callback leaked to original Client")
	}
	other, otherCancel := context.WithCancel(context.Background())
	defer otherCancel()
	if _, e = bound.Pull(other); !errors.Is(e, ErrVerifiedPullCommitScope) || calls.Load() != 0 {
		t.Fatal("foreign operation entered callback", e)
	}
	writer := f.writer(t)
	out, e := writer.Execute(ctx, bound, WriteRequest{ID: "commit-denied", Operation: "put", EnvironmentID: "env", Name: "TOKEN", Value: "SYNTHETIC"})
	if !errors.Is(e, callbackFailure) || out.Applied || f.posts != 0 || calls.Load() != 1 || f.engine.State().Cloud.Sequence != 1 {
		t.Fatal("commit failure allowed POST or unverified state", e)
	}
}
